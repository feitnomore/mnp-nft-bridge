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

package types

import (
	"fmt"

	"github.com/feitnomore/mnp-nft-bridge/pkg/utils"
	"github.com/google/nftables"
	"k8s.io/klog/v2"
)

/* CreateIngressChain queues the creation of a new pod-specific ingress chain. */
func (nft *NFTables) CreateIngressChain(chainSuffix string, tableFamily nftables.TableFamily) error {
	fullChainName := IngressChain + "_" + chainSuffix
	klog.V(5).Infof("[CreateIngressChain-Enqueue] Preparing to enqueue OpAddChain for ingress chain: %s", fullChainName)

	tableObj := nft.GetNftTableObject(TableFilter, tableFamily)
	if tableObj == nil {
		return fmt.Errorf("CreateIngressChain: could not get table object for %s/%v for chain %s", TableFilter, tableFamily, fullChainName)
	}

	chainObj := &nftables.Chain{
		Name:  fullChainName,
		Table: tableObj,
		Type:  nftables.ChainTypeFilter,
	}

	nft.EnqueueOperation(QueuedNftOperation{
		Type:        OpAddChain,
		Chain:       chainObj,
		Description: fmt.Sprintf("AddChain Ingress: %s", fullChainName),
	})
	klog.V(3).Infof("[CreateIngressChain-Enqueue] Enqueued OpAddChain for ingress chain: %s", fullChainName)
	return nil
}

/* CreateEgressChain queues the creation of a new pod-specific egress chain. */
func (nft *NFTables) CreateEgressChain(chainSuffix string, tableFamily nftables.TableFamily) error {
	fullChainName := EgressChain + "_" + chainSuffix
	klog.V(5).Infof("[CreateEgressChain-Enqueue] Preparing to enqueue OpAddChain for egress chain: %s", fullChainName)

	tableObj := nft.GetNftTableObject(TableFilter, tableFamily)
	if tableObj == nil {
		return fmt.Errorf("CreateEgressChain: could not get table object for %s/%v for chain %s", TableFilter, tableFamily, fullChainName)
	}

	chainObj := &nftables.Chain{
		Name:  fullChainName,
		Table: tableObj,
		Type:  nftables.ChainTypeFilter,
	}
	nft.EnqueueOperation(QueuedNftOperation{
		Type:        OpAddChain,
		Chain:       chainObj,
		Description: fmt.Sprintf("AddChain Egress: %s", fullChainName),
	})
	klog.V(3).Infof("[CreateEgressChain-Enqueue] Enqueued OpAddChain for egress chain: %s", fullChainName)
	return nil
}

/* DeletePodSpecificChain queues the FlushChain and DelChain operations. */
func (nft *NFTables) DeletePodSpecificChain(chainSuffix string, chainType string) error {
	var fullChainName string
	var tableFamilyForLookup nftables.TableFamily

	switch chainType {
	case IngressChainType:
		fullChainName = IngressChain + "_" + chainSuffix
		tableFamilyForLookup = nftables.TableFamilyBridge
	case EgressChainType:
		fullChainName = EgressChain + "_" + chainSuffix
		tableFamilyForLookup = nftables.TableFamilyBridge
	default:
		klog.Errorf("DeletePodSpecificChain: invalid chainType: %s for suffix %s", chainType, chainSuffix)
		return fmt.Errorf("DeletePodSpecificChain: invalid chainType: %s for suffix %s", chainType, chainSuffix)
	}
	klog.V(4).Infof("[DeletePodSpecificChain-Enqueue] Preparing to enqueue FlushChain & DelChain for: %s (type: %s)", fullChainName, chainType)

	tableObj := nft.GetNftTableObject(TableFilter, tableFamilyForLookup)
	if tableObj == nil {
		return fmt.Errorf("DeletePodSpecificChain: could not get table object for %s/%v for chain %s", TableFilter, tableFamilyForLookup, fullChainName)
	}
	chainToProcess := &nftables.Chain{Table: tableObj, Name: fullChainName, Type: nftables.ChainTypeFilter}

	nft.EnqueueOperation(QueuedNftOperation{
		Type:        OpFlushChain,
		Chain:       chainToProcess,
		Description: fmt.Sprintf("FlushChain: %s", fullChainName),
	})
	klog.V(5).Infof("[DeletePodSpecificChain-Enqueue] Enqueued OpFlushChain for %s", fullChainName)

	nft.EnqueueOperation(QueuedNftOperation{
		Type:        OpDelChain,
		Chain:       chainToProcess,
		Description: fmt.Sprintf("DelChain: %s", fullChainName),
	})
	klog.V(5).Infof("[DeletePodSpecificChain-Enqueue] Enqueued OpDelChain for %s", fullChainName)
	return nil
}

/* CleanupPodNftResources queues all cleanup operations for a given pod/policy. */
func (nft *NFTables) CleanupPodNftResources(
	podMac string,
	chainType string,
	fullChainNameToDelete string,
	chainSuffix string,
	isIsolationChain bool,
	policySpecificRuleCount int,
) error {
	klog.V(4).Infof("[CleanupPodNftResources-Enqueue] Cleanup called for MAC: %s, ChainType: %s, ChainToDel: %s, Suffix: %s, IsIsolation: %v, PolicyRuleCount: %d",
		podMac, chainType, fullChainNameToDelete, chainSuffix, isIsolationChain, policySpecificRuleCount)

	if podMac == "" {
		klog.Errorf("CleanupPodNftResources: pod MAC address is empty for chain %s (suffix %s)", fullChainNameToDelete, chainSuffix)
		return fmt.Errorf("CleanupPodNftResources: pod MAC address is empty for chain %s (suffix %s)", fullChainNameToDelete, chainSuffix)
	}

	var baseChainName string
	var ruleDirection string
	var hwOffset uint32
	var setTypes []NftSetType

	switch chainType {
	case IngressChainType:
		baseChainName = IngressChain
		ruleDirection = string(NftRuleDirectionIngress)
		hwOffset = DestinationHWOffset
		setTypes = []NftSetType{NftSetTypeSrcIP, NftSetTypeSrcMAC, NftSetTypeTCPPort, NftSetTypeUDPPort}
	case EgressChainType:
		baseChainName = EgressChain
		ruleDirection = string(NftRuleDirectionEgress)
		hwOffset = SourceHWOffset
		setTypes = []NftSetType{NftSetTypeDstIP, NftSetTypeDstMAC, NftSetTypeTCPPort, NftSetTypeUDPPort}
	default:
		return fmt.Errorf("CleanupPodNftResources: invalid chainType '%s'", chainType)
	}

	klog.V(4).Infof("[CleanupPodNftResources-Enqueue] Suffix %s: Enqueueing deletion of JUMP rule from %s to %s for MAC %s.", chainSuffix, baseChainName, fullChainNameToDelete, podMac)
	nft.EnqueueDeleteBridgeRuleJumpOnly(baseChainName, fullChainNameToDelete, podMac, hwOffset)

	klog.V(4).Infof("[CleanupPodNftResources-Enqueue] Suffix %s: Enqueueing flush & delete for chain %s.", chainSuffix, fullChainNameToDelete)
	tableObj := nft.GetNftTableObject(TableFilter, nftables.TableFamilyBridge)
	if tableObj == nil {
		klog.Errorf("[CleanupPodNftResources-Enqueue] Suffix %s: Could not get table object for chain %s. Skipping flush & delete.", chainSuffix, fullChainNameToDelete)
	} else {
		chainToProcess := &nftables.Chain{Table: tableObj, Name: fullChainNameToDelete, Type: nftables.ChainTypeFilter}
		nft.EnqueueOperation(QueuedNftOperation{
			Type:        OpFlushChain,
			Chain:       chainToProcess,
			Description: fmt.Sprintf("FlushChain: %s", fullChainNameToDelete),
		})
		nft.EnqueueOperation(QueuedNftOperation{
			Type:        OpDelChain,
			Chain:       chainToProcess,
			Description: fmt.Sprintf("DelChain: %s", fullChainNameToDelete),
		})
	}

	if !isIsolationChain && policySpecificRuleCount > 0 {
		klog.V(4).Infof("[CleanupPodNftResources-Enqueue] Suffix %s: Enqueueing cleanup of %s sets (RuleCount: %d).", chainSuffix, ruleDirection, policySpecificRuleCount)
		for ruleIdx := range policySpecificRuleCount {
			for _, setType := range setTypes {
				nft.deleteNftSet(chainSuffix, ruleDirection, ruleIdx, string(setType))
			}
		}
	} else {
		klog.V(4).Infof("[CleanupPodNftResources-Enqueue] Suffix %s: Skipping set cleanup for chain %s (IsIsolation: %v, RuleCount: %d).", chainSuffix, fullChainNameToDelete, isIsolationChain, policySpecificRuleCount)
	}

	klog.V(4).Infof("[CleanupPodNftResources-Enqueue] Suffix %s: Enqueueing deletion of direct DROP rules from base chains for MAC %s.", chainSuffix, podMac)
	nft.EnqueueDeleteIngressDropRule(podMac)
	nft.EnqueueDeleteEgressDropRule(podMac)

	klog.V(2).Infof("[CleanupPodNftResources-Enqueue] Suffix %s: Finished queueing relevant cleanup operations for chain %s.", chainSuffix, fullChainNameToDelete)
	return nil
}

func (nft *NFTables) VerifyChainAndSetsDeleted(
	chainSuffix string,
	metaChainType string,
	metaFullChainName string,
	metaIsIsolationChain bool,
	totalRuleEntriesForSetVerification int, /* Total number of 'from' or 'to' sections in MultiNetworkPolicy.spec */
) bool {
	var tableFamilyForLookup nftables.TableFamily

	if metaFullChainName == "" {
		klog.Warningf("[VerifyChainAndSetsDeleted] metaFullChainName is empty for suffix %s, type %s. This is unexpected.", chainSuffix, metaChainType)
		/* We cannot proceed reliably without the full chain name. */
		return false
	}

	klog.V(4).Infof("[VerifyChainAndSetsDeleted] Verifying deletion of chain %s (type: %s, isolation: %v, suffix: %s) and its associated sets.",
		metaFullChainName, metaChainType, metaIsIsolationChain, chainSuffix)

	switch metaChainType {
	case IngressChainType:
		tableFamilyForLookup = nftables.TableFamilyBridge
	case EgressChainType:
		tableFamilyForLookup = nftables.TableFamilyBridge
	default:
		klog.Errorf("[VerifyChainAndSetsDeleted] Invalid metaChainType received: %s for chain %s", metaChainType, metaFullChainName)
		return false /* Unknown chain type, we cannot verify */
	}

	targetTable := nft.GetNftTableObject(TableFilter, tableFamilyForLookup)
	if targetTable == nil {
		/* GetNftTableObject now returns a new reference if it's not found in the cache,
		 * so this nil check is more for extreme robustness or if the logic changes.
		 * The bigger problem would be if nft.conn were nil.
		 */
		klog.Errorf("[VerifyChainAndSetsDeleted] Could not get table object for %s/%v for chain %s verification", TableFilter, tableFamilyForLookup, metaFullChainName)
		return false
	}

	/* Check if the chain has been deleted
	 * ListChains is more reliable for checking for absence than GetChainByName,
	 * which may return an error other than "no such file" if the table does not exist.
	 */
	allChains, errList := nft.conn.ListChains()
	if errList != nil {
		klog.Warningf("[VerifyChainAndSetsDeleted] Error listing all chains: %v. Cannot reliably verify deletion of %s.", errList, metaFullChainName)
		return false /* We cannot confirm the deletion if we cannot list the chains */
	}

	chainFoundInList := false
	for _, ch := range allChains {
		if ch.Table != nil && ch.Name == metaFullChainName && ch.Table.Name == targetTable.Name && ch.Table.Family == targetTable.Family {
			chainFoundInList = true
			break
		}
	}

	if chainFoundInList {
		klog.Warningf("[VerifyChainAndSetsDeleted] Chain %s still found via ListChains in table %s/%s.", metaFullChainName, targetTable.Name, utils.DecodeTableFamily(targetTable.Family))
		return false /* Chain still exists */
	}
	klog.V(3).Infof("[VerifyChainAndSetsDeleted] Chain %s confirmed NOT FOUND via ListChains.", metaFullChainName)

	/* Set Verification (only makes sense if it wasn't isolation and there were rule entries in the MultiNetworkPolicy) */
	if !metaIsIsolationChain && totalRuleEntriesForSetVerification > 0 {
		var setTypesToCheck []NftSetType
		var ruleDirection string

		if metaChainType == IngressChainType {
			setTypesToCheck = []NftSetType{NftSetTypeSrcIP, NftSetTypeSrcMAC, NftSetTypeTCPPort, NftSetTypeUDPPort}
			ruleDirection = string(NftRuleDirectionIngress)
		} else { /* EgressChainType */
			setTypesToCheck = []NftSetType{NftSetTypeDstIP, NftSetTypeDstMAC, NftSetTypeTCPPort, NftSetTypeUDPPort}
			ruleDirection = string(NftRuleDirectionEgress)
		}

		klog.V(5).Infof("[VerifyChainAndSetsDeleted] Verifying deletion of sets for chain suffix %s (type %s), total rule entries in MNP spec: %d.", chainSuffix, metaChainType, totalRuleEntriesForSetVerification)

		for ruleIdx := range totalRuleEntriesForSetVerification {
			for _, setType := range setTypesToCheck {
				/* Rebuild the set name as you would in buildIPSet/buildHWSet/buildPortSet */
				deterministicSetIDStr := utils.GenerateDeterministicSetID(chainSuffix, ruleDirection, ruleIdx, string(setType))
				setName := "mnp-" + string(setType) + "-" + deterministicSetIDStr[:setSize]

				/* Try to get the set by name */
				_, errSet := nft.conn.GetSetByName(targetTable, setName)
				if errSet == nil {
					/* If there was no error, the set still exists */
					klog.Warningf("[VerifyChainAndSetsDeleted] Set %s (for chain suffix %s, MNP ruleIdx %d, type %s) still exists in kernel.", setName, chainSuffix, ruleIdx, setType)
					return false /* Set still exists */
				}
				/* If there was an error, check if it is the expected error "no such file or directory" */
				if !utils.IsNftNoSuchFileError(errSet) {
					/* Some other error occurred while trying to get the set */
					klog.Warningf("[VerifyChainAndSetsDeleted] Error checking set %s existence (expected 'no such file or directory', got: %v)", setName, errSet)
					return false /* We cannot confirm the deletion */
				}
				/* If the error was "no such file or directory", the set was deleted correctly. */
				klog.V(6).Infof("[VerifyChainAndSetsDeleted] Set %s (for MNP ruleIdx %d, type %s) confirmed deleted from kernel.", setName, ruleIdx, setType)
			}
		}
		klog.V(5).Infof("[VerifyChainAndSetsDeleted] All expected sets for chain suffix %s (type %s) confirmed deleted.", chainSuffix, metaChainType)
	} else {
		klog.V(5).Infof("[VerifyChainAndSetsDeleted] Skipping set deletion verification for chain %s (type %s) as it was an isolation chain or had no rule entries in MNP spec (TotalRuleEntries: %d, IsIsolation: %v).", metaFullChainName, metaChainType, totalRuleEntriesForSetVerification, metaIsIsolationChain)
	}

	klog.V(3).Infof("[VerifyChainAndSetsDeleted] All checks passed for chain suffix %s (type %s, full name: %s). Confirmed fully cleaned up from kernel.", chainSuffix, metaChainType, metaFullChainName)
	return true
}
