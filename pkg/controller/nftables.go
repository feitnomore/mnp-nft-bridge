/**
 * Copyright 2025 Marcelo Parisi (github.com/feitnomore)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package controller

import (
	"fmt"
	"sync"
	"time"

	"github.com/feitnomore/mnp-nft-bridge/pkg/cache"
	"github.com/feitnomore/mnp-nft-bridge/pkg/types"
	"github.com/feitnomore/mnp-nft-bridge/pkg/utils"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
)

/* Controller to handle Nftables interaction */
type NftablesController struct {
	nftctrl *types.NFTables
}

var (
	nftablesController NftablesController
	reconcileTrigger   chan struct{}
	reconcileMutex     sync.Mutex

	reconcileTimer    *time.Timer
	reconcileTimerMux sync.Mutex
)

const (
	reconcileQueueSize        = 1
	debounceDuration          = 250 * time.Millisecond
	periodicReconcileInterval = 60 * time.Second
	initialReconcileDelay     = 5 * time.Second
)

/* individualFlushFallback attempts to apply and flush a batch of nftables operations one by one.
 * This is used as a recovery mechanism when a full batch flush fails.
 */
func individualFlushFallback(nftCtrl *types.NFTables, batchToProcess []types.QueuedNftOperation, logEntryPrefix string, isCleanupOp bool) error {
	var opsToRequeueAfterIndividualFailure []types.QueuedNftOperation
	successfulIndividualOpsCount := 0

	for i, op := range batchToProcess {
		currentOp := op
		opDescriptionForLog := fmt.Sprintf("Op #%d/%d: %s - %s", i+1, len(batchToProcess), currentOp.Type, currentOp.Description)
		individualLogPrefix := fmt.Sprintf("%s INDIVIDUAL FALLBACK:", logEntryPrefix)

		klog.V(5).Infof("%s Attempting %s", individualLogPrefix, opDescriptionForLog)

		if errPrep := nftCtrl.ExecuteQueuedOperationOnConnection(&currentOp); errPrep != nil {
			klog.Errorf("%s Error preparing %s: %v. Adding this and subsequent ops to requeue list.", individualLogPrefix, opDescriptionForLog, errPrep)
			opsToRequeueAfterIndividualFailure = append(opsToRequeueAfterIndividualFailure, batchToProcess[i:]...)
			break
		}

		individualFlushErr := nftCtrl.Conn().Flush()
		if individualFlushErr == nil {
			klog.V(4).Infof("%s FLUSH SUCCEEDED after %s", individualLogPrefix, opDescriptionForLog)
			successfulIndividualOpsCount++
			continue
		}

		/* Error handling for individual flush */
		isDeletionOrFlushOp := (currentOp.Type == types.OpDelChain ||
			currentOp.Type == types.OpDelSet ||
			currentOp.Type == types.OpDelRule ||
			currentOp.Type == types.OpFlushSet ||
			currentOp.Type == types.OpFlushChain)

		isAddSetOp := (currentOp.Type == types.OpAddSet)
		isAcceptableAddSetError := (utils.IsNftSetExistsError(individualFlushErr) ||
			(utils.IsNftDeviceOrResourceBusyError(individualFlushErr) && isAddSetOp))

		isTolerableError := false
		if utils.IsNftNoSuchFileError(individualFlushErr) && (isDeletionOrFlushOp || isAddSetOp) {
			klog.V(4).Infof("%s Op %s for '%s' resulted in 'no such file or directory'. Assuming already handled or non-existent. Continuing fallback.", individualLogPrefix, currentOp.Type, currentOp.Description)
			isTolerableError = true
		} else if isAddSetOp && isAcceptableAddSetError {
			klog.V(4).Infof("%s OpAddSet for '%s' resulted in '%v'. Assuming set already exists or transient issue. Continuing fallback.", individualLogPrefix, currentOp.Description, individualFlushErr)
			isTolerableError = true
		}

		if isTolerableError {
			successfulIndividualOpsCount++
			continue
		}

		klog.Errorf("%s FLUSH FAILED after %s: %v", individualLogPrefix, opDescriptionForLog, individualFlushErr)
		if isCleanupOp {
			klog.Infof("%s Problematic operation details: Type: %s, Desc: %s", individualLogPrefix, currentOp.Type, currentOp.Description)
			if currentOp.Table != nil {
				klog.Infof("  Table: Name=%s, Family=%v", currentOp.Table.Name, currentOp.Table.Family)
			}
			if currentOp.Chain != nil {
				klog.Infof("  Chain: Name=%s, Type=%v, Hook=%v, Prio=%v", currentOp.Chain.Name, currentOp.Chain.Type, currentOp.Chain.Hooknum, currentOp.Chain.Priority)
			}
			if currentOp.Set != nil {
				klog.Infof("  Set: Name=%s, KeyType=%v, Constant=%v, Elements=%d", currentOp.Set.Name, currentOp.Set.KeyType, currentOp.Set.Constant, len(currentOp.SetElements))
			}
			if currentOp.Rule != nil {
				klog.Infof("  Rule: Chain=%s, NumExprs=%d", currentOp.Rule.Chain.Name, len(currentOp.Rule.Exprs))
			}
		}
		opsToRequeueAfterIndividualFailure = append(opsToRequeueAfterIndividualFailure, batchToProcess[i:]...)
		break
	}

	if len(opsToRequeueAfterIndividualFailure) > 0 {
		klog.Warningf("%s Re-queuing %d operations due to failure. %d ops succeeded individually before this.", logEntryPrefix, len(opsToRequeueAfterIndividualFailure), successfulIndividualOpsCount)
		nftCtrl.RequeueOperationsBatch(opsToRequeueAfterIndividualFailure)
		return fmt.Errorf("individual flush fallback failed after %d successful ops", successfulIndividualOpsCount)
	}

	klog.V(2).Infof("%s Successfully applied and flushed all %d operations individually.", logEntryPrefix, len(batchToProcess))
	return nil
}

func flushAndApplyQueuedOperations(cycleID string, nftCtrl *types.NFTables, operationDescription string) error {
	if !nftCtrl.HasPendingOperations() {
		klog.V(4).Infof("[CycleID: %s, OpDesc: %s] No pending NFTables operations to process and flush.", cycleID, operationDescription)
		return nil
	}

	batchToProcess := nftCtrl.DequeueOperationsBatch()
	if len(batchToProcess) == 0 {
		klog.V(5).Infof("[CycleID: %s, OpDesc: %s] Dequeued an empty batch, nothing to process.", cycleID, operationDescription)
		return nil
	}

	isCleanupOp := (operationDescription == "orphan cleanup")

	logEntryPrefix := fmt.Sprintf("[CycleID: %s, OpDesc: %s]", cycleID, operationDescription)
	if isCleanupOp {
		logEntryPrefix = fmt.Sprintf("[CycleID: %s, Cleanup]", cycleID)
		klog.Infof("%s Starting BATCH FLUSH strategy for %d ORPHAN CLEANUP operations.", logEntryPrefix, len(batchToProcess))
	} else {
		klog.V(3).Infof("%s Attempting BATCH FLUSH strategy for %d operations.", logEntryPrefix, len(batchToProcess))
	}

	maxBatchRetries := 3
	batchRetryDelay := 200 * time.Millisecond
	var lastBatchFlushErr error

	for attempt := 1; attempt <= maxBatchRetries; attempt++ {
		klog.V(4).Infof("%s BATCH FLUSH (Attempt %d/%d).", logEntryPrefix, attempt, maxBatchRetries)

		var opErrorsInBatch []string
		for i := range batchToProcess {
			op := &batchToProcess[i]
			klog.V(7).Infof("%s BATCH (Attempt %d): Preparing Op #%d/%d: %s - %s", logEntryPrefix, attempt, i+1, len(batchToProcess), op.Type, op.Description)
			if err := nftCtrl.ExecuteQueuedOperationOnConnection(op); err != nil {
				errMsg := fmt.Sprintf("Error preparing op %s (%s) for batch (Attempt %d): %v", op.Type, op.Description, attempt, err)
				klog.Warningf("%s %s", logEntryPrefix, errMsg)
				opErrorsInBatch = append(opErrorsInBatch, errMsg)
			}
		}

		if len(opErrorsInBatch) > 0 {
			klog.Warningf("%s BATCH (Attempt %d): Encountered %d errors during operation preparation. Proceeding with batch flush. Errors: %v", logEntryPrefix, attempt, len(opErrorsInBatch), opErrorsInBatch)
		}

		klog.V(4).Infof("%s BATCH (Attempt %d): Flushing %d operations.", logEntryPrefix, attempt, len(batchToProcess))
		flushStartTime := time.Now()
		lastBatchFlushErr = nftCtrl.Conn().Flush()
		flushDuration := time.Since(flushStartTime)

		if lastBatchFlushErr == nil {
			klog.V(2).Infof("%s BATCH FLUSH SUCCEEDED (Attempt %d, Duration: %s) for %d operations.", logEntryPrefix, attempt, flushDuration, len(batchToProcess))
			if len(opErrorsInBatch) > 0 {
				klog.Warningf("%s Note: Although batch flush succeeded, %d op preparation errors occurred. Review logs.", logEntryPrefix, len(opErrorsInBatch))
			}
			return nil
		}

		klog.Errorf("%s BATCH FLUSH FAILED (Attempt %d/%d, Duration: %s): %v.", logEntryPrefix, attempt, maxBatchRetries, flushDuration, lastBatchFlushErr)

		if attempt < maxBatchRetries && utils.IsNftDeviceOrResourceBusyError(lastBatchFlushErr) {
			klog.Warningf("%s Retrying batch flush due to 'device or resource busy' in %v...", logEntryPrefix, batchRetryDelay)
			time.Sleep(batchRetryDelay)
			batchRetryDelay *= 2
			continue
		}
		klog.Errorf("%s Unrecoverable batch flush error or max retries (%d/%d) reached. Last error: %v.", logEntryPrefix, attempt, maxBatchRetries, lastBatchFlushErr)
		break
	}

	if lastBatchFlushErr == nil {
		return nil
	}

	/* If batch flush failed, attempt individual fallback */
	klog.Warningf("%s BATCH FLUSH FAILED after %d attempts. Switching to INDIVIDUAL FLUSH strategy. Last batch error: %v", logEntryPrefix, maxBatchRetries, lastBatchFlushErr)
	fallbackErr := individualFlushFallback(nftCtrl, batchToProcess, logEntryPrefix, isCleanupOp)
	if fallbackErr != nil {
		return fmt.Errorf("batch flush failed for '%s' (last error: %v); %w", operationDescription, lastBatchFlushErr, fallbackErr)
	}

	return nil
}

/* resolvePolicyPeers resolves a list of MultiNetworkPolicyPeer objects into concrete IP blocks and MAC addresses. */
func resolvePolicyPeers(peers []multiv1beta1.MultiNetworkPolicyPeer, policyNamespace, mnpNetworkAnnotation string) ([]string, []string) {
	var resolvedIPBlocks []string
	var resolvedMacs []string

	for _, peer := range peers {
		if peer.IPBlock != nil {
			resolvedIPBlocks = append(resolvedIPBlocks, peer.IPBlock.CIDR)
			continue
		}

		var namespacesToSearch []string
		if peer.NamespaceSelector != nil {
			nsPolicyMap, err := metav1.LabelSelectorAsMap(peer.NamespaceSelector)
			if err != nil {
				klog.Warningf("Error converting NamespaceSelector: %v", err)
				continue
			}
			nsList, err := cache.GetNamespacesByLabels(nsPolicyMap)
			if err != nil || nsList == nil {
				klog.Warningf("Error getting namespaces by labels for selector %v: %v", nsPolicyMap, err)
				continue
			}
			for _, nsItem := range nsList.Items {
				namespacesToSearch = append(namespacesToSearch, nsItem.Name)
			}
		} else {
			/* If no namespace selector, the scope is the policy's own namespace. */
			namespacesToSearch = append(namespacesToSearch, policyNamespace)
		}

		for _, nsName := range namespacesToSearch {
			var podsToSearch *v1.PodList
			var err error
			if peer.PodSelector != nil {
				podsToSearch, err = cache.GetNamespacedPodsByLabels(nsName, peer.PodSelector.MatchLabels)
			} else {
				/* If no pod selector, select all pods in the namespace(s). */
				podsToSearch, err = cache.GetNamespacedPods(nsName)
			}

			if err != nil || podsToSearch == nil {
				klog.Warningf("Error getting pods in namespace %s: %v", nsName, err)
				continue
			}

			for i := range podsToSearch.Items {
				p := &podsToSearch.Items[i]
				peerNetStatus, _ := netdefutils.GetNetworkStatus(p)
				for _, status := range peerNetStatus {
					if utils.NormalizeNetworkName(status.Name, p.Namespace) == utils.NormalizeNetworkName(mnpNetworkAnnotation, policyNamespace) && status.Mac != "" {
						resolvedMacs = append(resolvedMacs, status.Mac)
						/* Found the correct network for this peer pod */
						break
					}
				}
			}
		}
	}
	return resolvedIPBlocks, resolvedMacs
}

/* processSinglePolicyForPod handles the application of a single policy to a single pod,
 * including ingress and egress rule generation.
 */
func processSinglePolicyForPod(nftCtrl *types.NFTables, policy *multiv1beta1.MultiNetworkPolicy, pod *v1.Pod, podMacOnManagedNet, mnpNetworkAnnotation string, activeChainCacheKeys map[string]bool) {
	policyIdentifier := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
	podIdentifier := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
	inputForHash := policyIdentifier + ":" + podIdentifier
	chainNameSuffix := utils.GenerateHash(inputForHash)

	/* Determine the *effective* rule counts based on active policy types.
	 * This is the correct value to store in the metadata.
	 */
	var effectiveIngressRuleCount, effectiveEgressRuleCount int
	if utils.HasPolicyType(policy, multiv1beta1.PolicyTypeIngress) {
		effectiveIngressRuleCount = len(policy.Spec.Ingress)
	}
	if utils.HasPolicyType(policy, multiv1beta1.PolicyTypeEgress) {
		effectiveEgressRuleCount = len(policy.Spec.Egress)
	}

	/*
	 * INGRESS
	 */
	if utils.HasPolicyType(policy, multiv1beta1.PolicyTypeIngress) {
		ingressCacheKey := chainNameSuffix + "_" + types.IngressChainType
		activeChainCacheKeys[ingressCacheKey] = true

		if len(policy.Spec.Ingress) > 0 {
			_, _ = ensureIngressChainAndJumpRule(nftCtrl, chainNameSuffix, policy.Name, policy.Namespace, effectiveIngressRuleCount, effectiveEgressRuleCount, 0, pod.Name, pod.Namespace, podMacOnManagedNet)
			ingressRuleChainFullName := types.IngressChain + "_" + chainNameSuffix
			if ingressRuleChain := nftCtrl.FindSpecChain(ingressRuleChainFullName); ingressRuleChain != nil {
				nftCtrl.EnqueueOperation(types.QueuedNftOperation{Type: types.OpFlushChain, Chain: ingressRuleChain, Description: fmt.Sprintf("FlushChain Ingress Rules (pre-render): %s", ingressRuleChain.Name)})
			}

			var totalRenderedIngress int
			for i, ingressRule := range policy.Spec.Ingress {
				resolvedIPs, resolvedMACs := resolvePolicyPeers(ingressRule.From, policy.Namespace, mnpNetworkAnnotation)
				totalRenderedIngress += nftCtrl.RenderIngressRules(chainNameSuffix, i, resolvedIPs, resolvedMACs, ingressRule.Ports, ingressRule.From, pod)
			}
			if meta, exists := cache.GetNftPodChainMetadata(ingressCacheKey); exists {
				meta.PolicyRuleCount = totalRenderedIngress
				cache.AddOrUpdateNftPodChainMetadata(ingressCacheKey, meta)
			}
		} else {
			_ = ensureIngressIsolationChainAndJumpRule(nftCtrl, chainNameSuffix, policy.Name, policy.Namespace, effectiveIngressRuleCount, effectiveEgressRuleCount, pod.Name, pod.Namespace, podMacOnManagedNet)
		}
	}

	/*
	 * EGRESS
	 */
	if utils.HasPolicyType(policy, multiv1beta1.PolicyTypeEgress) {
		egressCacheKey := chainNameSuffix + "_" + types.EgressChainType
		activeChainCacheKeys[egressCacheKey] = true

		if len(policy.Spec.Egress) > 0 {
			_, _ = ensureEgressChainAndJumpRule(nftCtrl, chainNameSuffix, policy.Name, policy.Namespace, effectiveIngressRuleCount, effectiveEgressRuleCount, 0, pod.Name, pod.Namespace, podMacOnManagedNet)
			egressRuleChainFullName := types.EgressChain + "_" + chainNameSuffix
			if egressRuleChain := nftCtrl.FindSpecChain(egressRuleChainFullName); egressRuleChain != nil {
				nftCtrl.EnqueueOperation(types.QueuedNftOperation{Type: types.OpFlushChain, Chain: egressRuleChain, Description: fmt.Sprintf("FlushChain Egress Rules (pre-render): %s", egressRuleChain.Name)})
			}

			var totalRenderedEgress int
			for i, egressRule := range policy.Spec.Egress {
				resolvedIPs, resolvedMACs := resolvePolicyPeers(egressRule.To, policy.Namespace, mnpNetworkAnnotation)
				totalRenderedEgress += nftCtrl.RenderEgressRules(chainNameSuffix, i, resolvedIPs, resolvedMACs, egressRule.Ports, pod)
			}
			if meta, exists := cache.GetNftPodChainMetadata(egressCacheKey); exists {
				meta.PolicyRuleCount = totalRenderedEgress
				cache.AddOrUpdateNftPodChainMetadata(egressCacheKey, meta)
			}
		} else {
			_ = ensureEgressIsolationChainAndJumpRule(nftCtrl, chainNameSuffix, policy.Name, policy.Namespace, effectiveIngressRuleCount, effectiveEgressRuleCount, pod.Name, pod.Namespace, podMacOnManagedNet)
		}
	}
}

func processActivePolicies(cycleID string, nftCtrl *types.NFTables) map[string]bool {
	activeChainCacheKeys := make(map[string]bool)
	podsSelectedByAnyPolicy := make(map[string]bool)
	multiNetworkPolicyList := cache.GetMultiNetworkPolicyCache()

	klog.V(5).Infof("[CycleID: %s, ActivePolicies] Processing %d MultiNetworkPolicies.", cycleID, len(multiNetworkPolicyList.Items))

	for i := range multiNetworkPolicyList.Items {
		thisPolicy := multiNetworkPolicyList.Items[i]
		policyIdentifier := fmt.Sprintf("%s/%s", thisPolicy.Namespace, thisPolicy.Name)
		klog.V(6).Infof("[CycleID: %s, ActivePolicies] Processing Policy: %s", cycleID, policyIdentifier)

		var policyPodSelector labels.Selector
		if thisPolicy.Spec.PodSelector.Size() == 0 {
			klog.V(5).Infof("[CycleID: %s, ActivePolicies] Policy %s has an empty podSelector (Size=0), will select all pods in namespace %s.", cycleID, policyIdentifier, thisPolicy.Namespace)
			policyPodSelector = labels.Everything()
		} else {
			var errSel error
			policyPodSelector, errSel = metav1.LabelSelectorAsSelector(&thisPolicy.Spec.PodSelector)
			if errSel != nil {
				klog.Warningf("[CycleID: %s, ActivePolicies] Policy %s: failed to convert podSelector to selector: %v. Skipping this policy.", cycleID, policyIdentifier, errSel)
				continue
			}
		}

		namespacedPods := cache.GetNamespacedPodsCache(thisPolicy.Namespace)
		if namespacedPods == nil || len(namespacedPods.Items) == 0 {
			klog.V(6).Infof("[CycleID: %s, ActivePolicies] No pods found in namespace %s for policy %s. Skipping pod iteration.", cycleID, thisPolicy.Namespace, policyIdentifier)
			continue
		}

		for j := range namespacedPods.Items {
			thisPodPtr := &namespacedPods.Items[j]
			podIdentifier := fmt.Sprintf("%s/%s", thisPodPtr.Namespace, thisPodPtr.Name)

			mnpPolicyForAnnotation, mnpPolicyForOK := thisPolicy.Annotations[types.PolicyForAnnotation]
			if !mnpPolicyForOK || mnpPolicyForAnnotation == "" {
				klog.V(7).Infof("[CycleID: %s, ActivePolicies] Policy %s does not have a '%s' annotation. Skipping pod %s for this policy.", cycleID, policyIdentifier, types.PolicyForAnnotation, podIdentifier)
				continue
			}

			podUsesCorrectNetwork := false
			var podMacOnManagedNet string
			podNetworkStatuses, errStatus := netdefutils.GetNetworkStatus(thisPodPtr)
			if errStatus != nil {
				klog.V(7).Infof("[CycleID: %s, ActivePolicies] Error getting network status for pod %s: %v. Skipping for policy %s.", cycleID, podIdentifier, errStatus, policyIdentifier)
				continue
			}
			for _, netStatus := range podNetworkStatuses {
				normalizedMnpNetRef := utils.NormalizeNetworkName(mnpPolicyForAnnotation, thisPolicy.Namespace)
				normalizedPodNetStatusName := utils.NormalizeNetworkName(netStatus.Name, thisPodPtr.Namespace)
				if normalizedPodNetStatusName == normalizedMnpNetRef {
					nadNamespace, nadName := utils.ParseNamespacedName(netStatus.Name, thisPodPtr.Namespace)
					netDriver := cache.GetNetworkAttachmentDefinitionDriver(nadNamespace, nadName)

					switch netDriver {
					case types.CNIDriverBridge:
						podUsesCorrectNetwork = true
						podMacOnManagedNet = netStatus.Mac
						klog.V(7).Infof("[CycleID: %s, ActivePolicies] Pod %s uses managed bridge network %s (driver: %s, MAC: %s).", cycleID, podIdentifier, normalizedMnpNetRef, netDriver, podMacOnManagedNet)
					case "":
						/* NAD not in cache. Check for existing metadata as a hint. */
						policyIdentifierForHash := fmt.Sprintf("%s/%s", thisPolicy.Namespace, thisPolicy.Name)
						podIdentifierForHash := fmt.Sprintf("%s/%s", thisPodPtr.Namespace, thisPodPtr.Name)
						inputForHash := policyIdentifierForHash + ":" + podIdentifierForHash
						chainNameSuffix := utils.GenerateHash(inputForHash)

						_, ingressMetaExists := cache.GetNftPodChainMetadata(chainNameSuffix + "_" + types.IngressChainType)
						_, egressMetaExists := cache.GetNftPodChainMetadata(chainNameSuffix + "_" + types.EgressChainType)

						if ingressMetaExists || egressMetaExists {
							klog.V(4).Infof("[CycleID: %s, ActivePolicies] Pod %s on network %s. NAD %s/%s not found, but existing metadata found. Assuming managed network and preserving state.", cycleID, podIdentifier, normalizedMnpNetRef, nadNamespace, nadName)
							podUsesCorrectNetwork = true
							podMacOnManagedNet = netStatus.Mac
						}
					}
					break
				}
			}
			if !podUsesCorrectNetwork {
				klog.V(7).Infof("[CycleID: %s, ActivePolicies] Pod %s does not use the managed bridge network '%s' specified by policy %s, or MAC not found. Skipping.", cycleID, podIdentifier, mnpPolicyForAnnotation, policyIdentifier)
				continue
			}
			if podMacOnManagedNet == "" {
				klog.Warningf("[CycleID: %s, ActivePolicies] Pod %s is on managed bridge network %s but MAC address is empty. Skipping.", cycleID, podIdentifier, mnpPolicyForAnnotation)
				continue
			}
			if !policyPodSelector.Matches(labels.Set(thisPodPtr.Labels)) {
				if thisPolicy.Spec.PodSelector.Size() != 0 {
					klog.V(8).Infof("[CycleID: %s, ActivePolicies] Pod %s does not match policy %s specific selector.", cycleID, podIdentifier, policyIdentifier)
				}
				continue
			}
			klog.V(7).Infof("[CycleID: %s, ActivePolicies] Pod %s is selected by policy %s (selector matched or was empty/everything).", cycleID, podIdentifier, policyIdentifier)

			podsSelectedByAnyPolicy[podMacOnManagedNet] = true

			processSinglePolicyForPod(nftCtrl, &thisPolicy, thisPodPtr, podMacOnManagedNet, mnpPolicyForAnnotation, activeChainCacheKeys)
		}
	}

	klog.V(4).Infof("[CycleID: %s, ActivePolicies] Ensuring DROP rules for %d unique pods selected by policies.", cycleID, len(podsSelectedByAnyPolicy))
	for mac := range podsSelectedByAnyPolicy {
		nftCtrl.EnsurePodIngressDropRule(mac)
		nftCtrl.EnsurePodEgressDropRule(mac)
	}

	return activeChainCacheKeys
}

func processOrphanedResources(cycleID string, nftCtrl *types.NFTables, activeChainCacheKeys map[string]bool) map[string]types.PodChainMetadata {
	suffixesProcessedForCleanup := make(map[string]types.PodChainMetadata)
	keysOrphanedAndCleanupAttempted := make(map[string]types.PodChainMetadata)

	allCachedMetadataKeys := cache.GetAllNftPodChainMetadataKeys()
	klog.V(5).Infof("[CycleID: %s, OrphanCleanup] Found %d keys in NftPodChainMetadataCache.", cycleID, len(allCachedMetadataKeys))

	for _, cachedKey := range allCachedMetadataKeys {
		if _, isActive := activeChainCacheKeys[cachedKey]; !isActive {
			meta, existsInCache := cache.GetNftPodChainMetadata(cachedKey)
			if !existsInCache {
				klog.Warningf("[CycleID: %s, OrphanCleanup] CRITICAL: Metadata for key '%s' (expected to be in cache) not found during orphan processing. Skipping.", cycleID, cachedKey)
				continue
			}
			keysOrphanedAndCleanupAttempted[cachedKey] = meta

			/* Track cleanup by chain suffix to avoid enqueuing duplicate set deletions
			 * when both ingress and egress chains for a pod/policy are orphaned.
			 */
			if _, alreadyProcessedThisMetaKey := suffixesProcessedForCleanup[cachedKey]; !alreadyProcessedThisMetaKey {
				klog.Infof("[DEBUG-CLEANUP] Orphaned key '%s'. Metadata from cache: PolicyName: %s/%s, Pod: %s/%s, MAC: %s, ChainType: %s, FullChainName: %s, Suffix: %s, IsIsolation: %t, PolicyIngressRuleCount: %d, PolicyEgressRuleCount: %d, PolicyRuleCount: %d",
					cachedKey, meta.PolicyNamespace, meta.PolicyName, meta.PodNamespace, meta.PodName, meta.PodMac, meta.ChainType, meta.FullChainName, meta.ChainSuffix, meta.IsIsolationChain, meta.PolicyIngressRuleCount, meta.PolicyEgressRuleCount, meta.PolicyRuleCount)

				klog.V(3).Infof("[CycleID: %s, OrphanCleanup] Orphaned metadata key %s identified. FullChainName: %s, Pod: %s/%s, Policy: %s/%s, IsIsolation: %v, PolicyIngressRuleCount (from meta): %d, PolicyEgressRuleCount (from meta): %d, PolicyRuleCount (rendered for this chain): %d. Preparing for cleanup.",
					cycleID, cachedKey, meta.FullChainName, meta.PodNamespace, meta.PodName, meta.PolicyNamespace, meta.PolicyName, meta.IsIsolationChain, meta.PolicyIngressRuleCount, meta.PolicyEgressRuleCount, meta.PolicyRuleCount)

				/* Use the MNP spec rule count for cleanup, as sets are always created per rule entry. */
				var totalRuleEntriesForSetCleanup int
				switch meta.ChainType {
				case types.IngressChainType:
					totalRuleEntriesForSetCleanup = meta.PolicyIngressRuleCount
				case types.EgressChainType:
					totalRuleEntriesForSetCleanup = meta.PolicyEgressRuleCount
				default:
					klog.Warningf("[CycleID: %s, OrphanCleanup] Unknown ChainType '%s' for metadata key %s. Using meta.PolicyRuleCount (%d) for set cleanup as a fallback, but this might be incorrect.",
						cycleID, meta.ChainType, cachedKey, meta.PolicyRuleCount)
					totalRuleEntriesForSetCleanup = meta.PolicyRuleCount
				}

				klog.V(4).Infof("[CycleID: %s, OrphanCleanup] For key %s (ChainType: %s), using totalRuleEntriesForSetCleanup: %d for CleanupPodNftResources.",
					cycleID, cachedKey, meta.ChainType, totalRuleEntriesForSetCleanup)

				if err := nftCtrl.CleanupPodNftResources(
					meta.PodMac,
					meta.ChainType,
					meta.FullChainName,
					meta.ChainSuffix,
					meta.IsIsolationChain,
					totalRuleEntriesForSetCleanup,
				); err != nil {
					klog.Errorf("[CycleID: %s, OrphanCleanup] Error queueing cleanup for key %s (Chain: %s, Suffix: %s): %v",
						cycleID, cachedKey, meta.FullChainName, meta.ChainSuffix, err)
				} else {
					klog.V(2).Infof("[CycleID: %s, OrphanCleanup] Successfully queued cleanup for key %s (Chain: %s, Suffix: %s).", cycleID, cachedKey, meta.FullChainName, meta.ChainSuffix)
					suffixesProcessedForCleanup[cachedKey] = meta
				}
			} else {
				klog.V(5).Infof("[CycleID: %s, OrphanCleanup] Metadata key %s (Chain: %s, Suffix: %s) already had cleanup queued (likely due to its counterpart chain type for the same suffix). Skipping redundant set cleanup logic.",
					cycleID, cachedKey, meta.FullChainName, meta.ChainSuffix)
			}
		}
	}
	return keysOrphanedAndCleanupAttempted
}

func reconcileMultiNetworkPolicies(cycleID string) {
	klog.V(4).Infof("[CycleID: %s] ReconcileMNP: ActualReconcileLoop started.", cycleID)

	nftablesController.nftctrl.LockConnection()
	klog.V(5).Infof("[CycleID: %s] ReconcileMNP: NFTables connection lock acquired.", cycleID)
	defer func() {
		klog.V(3).Infof("[CycleID: %s] ReconcileMNP: Triggering NFTables cache reload (internal) at the end of reconcile cycle.", cycleID)
		nftablesController.nftctrl.ReloadNftTableCacheInternal()
		nftablesController.nftctrl.UnlockConnection()
		klog.V(5).Infof("[CycleID: %s] ReconcileMNP: NFTables connection lock released.", cycleID)
	}()

	klog.V(4).Infof("[CycleID: %s] ReconcileMNP: Phase 1: Processing active policies.", cycleID)
	activeChainCacheKeys := processActivePolicies(cycleID, nftablesController.nftctrl)

	if nftablesController.nftctrl.HasPendingOperations() {
		err := flushAndApplyQueuedOperations(cycleID, nftablesController.nftctrl, "apply/update active policies")
		if err != nil {
			klog.Errorf("[CycleID: %s] ReconcileMNP: CRITICAL: Failed to flush active policy operations: %v. State may be inconsistent. Aborting further nftables changes in THIS reconcile cycle.", cycleID, err)
			return
		}
		klog.V(3).Infof("[CycleID: %s] ReconcileMNP: Successfully flushed active policy operations.", cycleID)
	} else {
		klog.V(4).Infof("[CycleID: %s] ReconcileMNP: No active policy operations were queued. Skipping policy flush.", cycleID)
	}

	klog.V(4).Infof("[CycleID: %s] ReconcileMNP: Phase 2: Processing orphaned resources (chains and sets).", cycleID)
	keysThatWereOrphanedAndAttemptedCleanup := processOrphanedResources(cycleID, nftablesController.nftctrl, activeChainCacheKeys)
	var cleanupFlushError error

	if nftablesController.nftctrl.HasPendingOperations() {
		cleanupFlushError = flushAndApplyQueuedOperations(cycleID, nftablesController.nftctrl, "orphan cleanup")
		if cleanupFlushError != nil {
			klog.Errorf("[CycleID: %s] ReconcileMNP: CRITICAL: Failed to flush orphan cleanup operations: %v. Metadata cache will not be updated for these orphans in this cycle. Aborting further nftables changes in THIS reconcile cycle.", cycleID, cleanupFlushError)
			return
		}
		klog.V(3).Infof("[CycleID: %s] ReconcileMNP: Successfully flushed orphan cleanup operations.", cycleID)
	} else {
		klog.V(4).Infof("[CycleID: %s] ReconcileMNP: No orphan cleanup operations were queued. Skipping cleanup flush.", cycleID)
	}

	if len(keysThatWereOrphanedAndAttemptedCleanup) > 0 {
		if cleanupFlushError == nil {
			klog.V(3).Infof("[CycleID: %s] ReconcileMNP: Verifying kernel state for %d orphaned metadata keys for cache cleanup.", cycleID, len(keysThatWereOrphanedAndAttemptedCleanup))

			for key, metaFromOrphanList := range keysThatWereOrphanedAndAttemptedCleanup {
				var totalRuleEntriesForVerification int
				switch metaFromOrphanList.ChainType {
				case types.IngressChainType:
					totalRuleEntriesForVerification = metaFromOrphanList.PolicyIngressRuleCount
				case types.EgressChainType:
					totalRuleEntriesForVerification = metaFromOrphanList.PolicyEgressRuleCount
				}

				if metaFromOrphanList.IsIsolationChain {
					totalRuleEntriesForVerification = 0
				}

				isClean := nftablesController.nftctrl.VerifyChainAndSetsDeleted(
					metaFromOrphanList.ChainSuffix,
					metaFromOrphanList.ChainType,
					metaFromOrphanList.FullChainName,
					metaFromOrphanList.IsIsolationChain,
					totalRuleEntriesForVerification,
				)

				if isClean {
					klog.V(2).Infof("[CycleID: %s] ReconcileMNP: Confirmed kernel cleanup for resources associated with metadata key: %s (Chain: %s). Removing from NftPodChainMetadataCache.", cycleID, key, metaFromOrphanList.FullChainName)
					cache.DeleteNftPodChainMetadata(key)
				} else {
					klog.Warningf("[CycleID: %s] ReconcileMNP: Kernel resources for metadata key: %s (Chain: %s) were NOT fully cleaned up. Metadata NOT removed from cache.", cycleID, key, metaFromOrphanList.FullChainName)
				}
			}
		} else {
			klog.Warningf("[CycleID: %s] ReconcileMNP: Skipping NftPodChainMetadataCache cleanup due to previous flush error during orphan cleanup.", cycleID)
		}
	} else {
		klog.V(4).Infof("[CycleID: %s] ReconcileMNP: No orphaned keys were identified for metadata cache update.", cycleID)
	}
	klog.V(4).Infof("[CycleID: %s] ReconcileMNP: Finished reconcileMultiNetworkPolicies cycle.", cycleID)
}

func NewNftablesController(nft *types.NFTables) {
	klog.V(8).Infof("Initializing NftablesController singleton.")
	nftablesController.nftctrl = nft
	if reconcileTrigger == nil {
		reconcileTrigger = make(chan struct{}, reconcileQueueSize)
	}
}

func StartNftController() {
	klog.V(2).Infof("Starting NftablesController main reconciliation processing loop.")
	go func() {
		time.Sleep(initialReconcileDelay)
		klog.V(4).Info("Initial reconciliation triggered by StartNftController.")
		ForceReconcile()
	}()

	ticker := time.NewTicker(periodicReconcileInterval)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				klog.V(5).Info("Periodic reconciliation triggered by ticker.")
				actualReconcileLoop()
			case _, ok := <-reconcileTrigger:
				if !ok {
					klog.Info("Reconcile trigger channel closed, exiting reconciliation loop.")
					return
				}
				klog.V(5).Info("Debounced reconciliation triggered via channel.")
				actualReconcileLoop()
				select {
				case <-ticker.C:
					klog.V(6).Info("Drained pending ticker event after forced reconcile.")
				default:
				}
			}
		}
	}()
}

func actualReconcileLoop() {
	if !reconcileMutex.TryLock() {
		klog.V(5).Info("ActualReconcileLoop: Reconciliation already in progress, skipping this trigger.")
		return
	}
	defer reconcileMutex.Unlock()

	cycleID := utils.GenerateRandomShortID()
	klog.V(4).Infof("[CycleID: %s] ActualReconcileLoop started.", cycleID)
	reconcileMultiNetworkPolicies(cycleID)
	klog.V(4).Infof("[CycleID: %s] ActualReconcileLoop finished.", cycleID)
}

func ForceReconcile() {
	reconcileTimerMux.Lock()
	defer reconcileTimerMux.Unlock()

	if reconcileTimer != nil {
		if !reconcileTimer.Stop() {
			klog.V(6).Info("ForceReconcile: Timer had already fired or was stopped.")
		} else {
			klog.V(5).Info("ForceReconcile: Stopped existing timer.")
		}
	}

	klog.V(4).Infof("ForceReconcile: (Re)starting debounce timer for %v.", debounceDuration)
	reconcileTimer = time.AfterFunc(debounceDuration, func() {
		klog.V(5).Info("Debounce timer expired. Attempting to send to reconcileTrigger channel.")
		select {
		case reconcileTrigger <- struct{}{}:
			klog.V(5).Info("Debounce timer: Signal successfully sent to reconcileTrigger channel.")
		default:
			klog.V(5).Info("Debounce timer: reconcileTrigger channel is full or no listener currently. Reconciliation will occur on next cycle.")
		}
	})
}

/* ensureIngressChainAndJumpRule queues the creation of a pod-specific ingress chain and its jump rule.
 * It stores metadata where `PolicyIngressRuleCount` is the MNP spec rule count, while `PolicyRuleCount`
 * is the count of nftables rules actually rendered for this specific chain.
 */
func ensureIngressChainAndJumpRule(
	nftCtrl *types.NFTables,
	chainNameSuffix string,
	policyName, policyNamespace string,
	/* Effective counts based on policyTypes for general metadata fields */
	metaIngressRuleCount, metaEgressRuleCount int,
	/* Count of nftables rules actually rendered for this specific chain */
	actuallyRenderedRulesForThisChain int,
	podName, podNamespace, podMac string,
) (string, error) {
	fullRuleChainName := types.IngressChain + "_" + chainNameSuffix
	cacheKey := chainNameSuffix + "_" + types.IngressChainType

	klog.V(4).Infof("[ensureIngressChainAndJumpRule] Enqueueing for ingress RULE chain %s (MAC: %s, Policy: %s/%s, Pod: %s/%s)",
		fullRuleChainName, podMac, policyNamespace, policyName, podNamespace, podName)

	tableObj := nftCtrl.GetNftTableObject(types.TableFilter, nftables.TableFamilyBridge)
	if tableObj == nil {
		return "", fmt.Errorf("ensureIngressChainAndJumpRule: could not get table object")
	}

	ruleChainObj := &nftables.Chain{
		Name:  fullRuleChainName,
		Table: tableObj,
		Type:  nftables.ChainTypeFilter,
	}
	nftCtrl.EnqueueOperation(types.QueuedNftOperation{
		Type:        types.OpAddChain,
		Chain:       ruleChainObj,
		Description: fmt.Sprintf("Add ingress rule chain %s", fullRuleChainName),
	})

	nftCtrl.EnqueueCreateBridgeRuleJumpOnly(types.IngressChain, fullRuleChainName, podMac, types.DestinationHWOffset)

	meta := types.PodChainMetadata{
		PolicyName:             policyName,
		PolicyNamespace:        policyNamespace,
		PodName:                podName,
		PodNamespace:           podNamespace,
		PodMac:                 podMac,
		ChainType:              types.IngressChainType,
		FullChainName:          fullRuleChainName,
		ChainSuffix:            chainNameSuffix,
		PolicyRuleCount:        actuallyRenderedRulesForThisChain, /* Use the count of effectively rendered rules */
		IsIsolationChain:       false,
		PolicyIngressRuleCount: metaIngressRuleCount, /* Reflects what policyTypes + spec.ingress would allow */
		PolicyEgressRuleCount:  metaEgressRuleCount,  /* Reflects what policyTypes + spec.egress would allow */
	}
	klog.V(5).Infof("[ensureIngressChainAndJumpRule] Storing/Updating metadata for key %s: %+v", cacheKey, meta)
	cache.AddOrUpdateNftPodChainMetadata(cacheKey, meta)

	return chainNameSuffix, nil
}

func ensureEgressChainAndJumpRule(
	nftCtrl *types.NFTables,
	chainNameSuffix string,
	policyName, policyNamespace string,
	metaIngressRuleCount, metaEgressRuleCount int,
	actuallyRenderedRulesForThisChain int,
	podName, podNamespace, podMac string,
) (string, error) {
	fullRuleChainName := types.EgressChain + "_" + chainNameSuffix
	cacheKey := chainNameSuffix + "_" + types.EgressChainType

	klog.V(4).Infof("[ensureEgressChainAndJumpRule] Enqueueing for egress RULE chain %s (MAC: %s, Policy: %s/%s, Pod: %s/%s)",
		fullRuleChainName, podMac, policyNamespace, policyName, podNamespace, podName)

	tableObj := nftCtrl.GetNftTableObject(types.TableFilter, nftables.TableFamilyBridge)
	if tableObj == nil {
		return "", fmt.Errorf("ensureEgressChainAndJumpRule: could not get table object")
	}

	ruleChainObj := &nftables.Chain{
		Name:  fullRuleChainName,
		Table: tableObj,
		Type:  nftables.ChainTypeFilter,
	}
	nftCtrl.EnqueueOperation(types.QueuedNftOperation{
		Type:        types.OpAddChain,
		Chain:       ruleChainObj,
		Description: fmt.Sprintf("Add egress rule chain %s", fullRuleChainName),
	})

	nftCtrl.EnqueueCreateBridgeRuleJumpOnly(types.EgressChain, fullRuleChainName, podMac, types.SourceHWOffset)

	meta := types.PodChainMetadata{
		PolicyName:             policyName,
		PolicyNamespace:        policyNamespace,
		PodName:                podName,
		PodNamespace:           podNamespace,
		PodMac:                 podMac,
		ChainType:              types.EgressChainType,
		FullChainName:          fullRuleChainName,
		ChainSuffix:            chainNameSuffix,
		PolicyRuleCount:        actuallyRenderedRulesForThisChain, /* Use the count of effectively rendered rules */
		IsIsolationChain:       false,
		PolicyIngressRuleCount: metaIngressRuleCount,
		PolicyEgressRuleCount:  metaEgressRuleCount,
	}
	klog.V(5).Infof("[ensureEgressChainAndJumpRule] Storing/Updating metadata for key %s: %+v", cacheKey, meta)
	cache.AddOrUpdateNftPodChainMetadata(cacheKey, meta)

	return chainNameSuffix, nil
}

func ensureIngressIsolationChainAndJumpRule(
	nftCtrl *types.NFTables,
	chainNameSuffix string,
	policyName, policyNamespace string,
	metaIngressRuleCount, metaEgressRuleCount int,
	podName, podNamespace, podMac string,
) error {
	fullIsolationChainName := types.IngressChain + "_ISOLATION_" + chainNameSuffix
	cacheKey := chainNameSuffix + "_" + types.IngressChainType

	klog.V(4).Infof("[ensureIngressIsolationChainAndJumpRule] Ensuring ingress isolation chain %s (MAC: %s, Policy: %s/%s, Pod: %s/%s)",
		fullIsolationChainName, podMac, policyNamespace, policyName, podNamespace, podName)

	tableObj := nftCtrl.GetNftTableObject(types.TableFilter, nftables.TableFamilyBridge)
	if tableObj == nil {
		return fmt.Errorf("ensureIngressIsolationChainAndJumpRule: could not get table object")
	}

	isolationChainObj := &nftables.Chain{Name: fullIsolationChainName, Table: tableObj, Type: nftables.ChainTypeFilter}
	nftCtrl.EnqueueOperation(types.QueuedNftOperation{Type: types.OpAddChain, Chain: isolationChainObj, Description: fmt.Sprintf("Add/Ensure ingress isolation chain %s", fullIsolationChainName)})
	nftCtrl.EnqueueOperation(types.QueuedNftOperation{Type: types.OpFlushChain, Chain: isolationChainObj, Description: fmt.Sprintf("Flush ingress isolation chain %s", fullIsolationChainName)})

	dropRuleExprs := []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
	dropRule := &nftables.Rule{Table: tableObj, Chain: isolationChainObj, Exprs: dropRuleExprs}
	nftCtrl.EnqueueOperation(types.QueuedNftOperation{Type: types.OpAddRule, Rule: dropRule, Description: fmt.Sprintf("Add DROP rule to ingress isolation chain %s", fullIsolationChainName)})
	nftCtrl.EnqueueCreateBridgeRuleJumpOnly(types.IngressChain, fullIsolationChainName, podMac, types.DestinationHWOffset)

	meta := types.PodChainMetadata{
		PolicyName:             policyName,
		PolicyNamespace:        policyNamespace,
		PodName:                podName,
		PodNamespace:           podNamespace,
		PodMac:                 podMac,
		ChainType:              types.IngressChainType,
		FullChainName:          fullIsolationChainName,
		ChainSuffix:            chainNameSuffix,
		PolicyRuleCount:        0,
		IsIsolationChain:       true,
		PolicyIngressRuleCount: metaIngressRuleCount,
		PolicyEgressRuleCount:  metaEgressRuleCount,
	}
	klog.V(5).Infof("[ensureIngressIsolationChainAndJumpRule] Storing/Updating metadata for key %s: %+v", cacheKey, meta)
	cache.AddOrUpdateNftPodChainMetadata(cacheKey, meta)
	return nil
}

func ensureEgressIsolationChainAndJumpRule(
	nftCtrl *types.NFTables,
	chainNameSuffix string,
	policyName, policyNamespace string,
	metaIngressRuleCount, metaEgressRuleCount int,
	podName, podNamespace, podMac string,
) error {
	fullIsolationChainName := types.EgressChain + "_ISOLATION_" + chainNameSuffix
	cacheKey := chainNameSuffix + "_" + types.EgressChainType

	klog.V(4).Infof("[ensureEgressIsolationChainAndJumpRule] Ensuring egress isolation chain %s (MAC: %s, Policy: %s/%s, Pod: %s/%s)",
		fullIsolationChainName, podMac, policyNamespace, policyName, podNamespace, podName)

	tableObj := nftCtrl.GetNftTableObject(types.TableFilter, nftables.TableFamilyBridge)
	if tableObj == nil {
		return fmt.Errorf("ensureEgressIsolationChainAndJumpRule: could not get table object")
	}

	isolationChainObj := &nftables.Chain{Name: fullIsolationChainName, Table: tableObj, Type: nftables.ChainTypeFilter}
	nftCtrl.EnqueueOperation(types.QueuedNftOperation{Type: types.OpAddChain, Chain: isolationChainObj, Description: fmt.Sprintf("Add/Ensure egress isolation chain %s", fullIsolationChainName)})
	nftCtrl.EnqueueOperation(types.QueuedNftOperation{Type: types.OpFlushChain, Chain: isolationChainObj, Description: fmt.Sprintf("Flush egress isolation chain %s", fullIsolationChainName)})

	dropRuleExprs := []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
	dropRule := &nftables.Rule{Table: tableObj, Chain: isolationChainObj, Exprs: dropRuleExprs}
	nftCtrl.EnqueueOperation(types.QueuedNftOperation{Type: types.OpAddRule, Rule: dropRule, Description: fmt.Sprintf("Add DROP rule to egress isolation chain %s", fullIsolationChainName)})
	nftCtrl.EnqueueCreateBridgeRuleJumpOnly(types.EgressChain, fullIsolationChainName, podMac, types.SourceHWOffset)

	meta := types.PodChainMetadata{
		PolicyName:             policyName,
		PolicyNamespace:        policyNamespace,
		PodName:                podName,
		PodNamespace:           podNamespace,
		PodMac:                 podMac,
		ChainType:              types.EgressChainType,
		FullChainName:          fullIsolationChainName,
		ChainSuffix:            chainNameSuffix,
		PolicyRuleCount:        0,
		IsIsolationChain:       true,
		PolicyIngressRuleCount: metaIngressRuleCount,
		PolicyEgressRuleCount:  metaEgressRuleCount,
	}
	klog.V(5).Infof("[ensureEgressIsolationChainAndJumpRule] Storing/Updating metadata for key %s: %+v", cacheKey, meta)
	cache.AddOrUpdateNftPodChainMetadata(cacheKey, meta)
	return nil
}
