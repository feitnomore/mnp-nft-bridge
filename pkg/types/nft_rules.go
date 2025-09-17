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
	"bytes" // Para normalizar e comparar expressões de regras
	"fmt"
	"net"

	// Se for usar regex para normalização mais avançada

	"github.com/feitnomore/mnp-nft-bridge/pkg/utils"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"k8s.io/klog/v2"
)

/* EnqueueDeleteBridgeRuleJump queues the deletion of a specific jump rule.
 * If the rule is not found in the cache with a valid handle, the delete operation is skipped.
 * EnqueueDeleteBridgeRuleJumpOnly queues the deletion of a specific JUMP rule,
 * without attempting to delete a subsequent DROP rule.
 */
func (nft *NFTables) EnqueueDeleteBridgeRuleJumpOnly(parentChainName, targetPodChainName, podMac string, hwOffset uint32) {
	mac, err := net.ParseMAC(podMac)
	if err != nil {
		klog.Errorf("EnqueueDeleteBridgeRuleJumpOnly: Invalid MAC address %s: %v", podMac, err)
		return
	}

	tableObj := nft.GetNftTableObject(TableFilter, nftables.TableFamilyBridge)
	if tableObj == nil {
		klog.Errorf("EnqueueDeleteBridgeRuleJumpOnly: Table %s/%v not found for base chain %s.", TableFilter, nftables.TableFamilyBridge, parentChainName)
		return
	}

	parentChainObj := nft.FindChainByNameAndFamily(parentChainName, nftables.TableFamilyBridge)
	if parentChainObj == nil {
		klog.V(4).Infof("[NFTables.EnqueueDeleteBridgeRuleJumpOnly] Parent chain %s not found in cache. Assuming JUMP rule for MAC %s to %s does not exist or already deleted. Skipping OpDelRule.", parentChainName, podMac, targetPodChainName)
		return
	}

	jumpRuleExprsToMatch := []expr.Any{
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: hwOffset, Len: HWLength},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: mac},
		&expr.Verdict{Kind: expr.VerdictJump, Chain: targetPodChainName},
	}

	var ruleToDelWithHandle *nftables.Rule
	rulesInParentChain := nft.getRulesFromCachedChain(parentChainObj)

	desiredSignature := utils.NormalizeExprsForComparison(jumpRuleExprsToMatch)
	for _, existingRule := range rulesInParentChain {
		isPotentiallySameRule := false
		if len(existingRule.Exprs) == 3 {
			if p, pOk := existingRule.Exprs[0].(*expr.Payload); pOk {
				if c, cOk := existingRule.Exprs[1].(*expr.Cmp); cOk {
					if v, vOk := existingRule.Exprs[2].(*expr.Verdict); vOk {
						if p.Base == expr.PayloadBaseLLHeader && p.Offset == hwOffset &&
							bytes.Equal(c.Data, mac) &&
							v.Kind == expr.VerdictJump && v.Chain == targetPodChainName {
							isPotentiallySameRule = true
						}
					}
				}
			}
		}

		if isPotentiallySameRule {
			if utils.NormalizeExprsForComparison(existingRule.Exprs) == desiredSignature {
				ruleCopy := existingRule
				ruleToDelWithHandle = &ruleCopy
				klog.V(5).Infof("[NFTables.EnqueueDeleteBridgeRuleJumpOnly] Found JUMP rule to delete by content in cache (Handle: %d) for MAC %s in %s", ruleToDelWithHandle.Handle, podMac, parentChainName)
				break
			}
		}
	}

	if ruleToDelWithHandle != nil && ruleToDelWithHandle.Handle != 0 {
		nft.EnqueueOperation(QueuedNftOperation{
			Type:        OpDelRule,
			Rule:        ruleToDelWithHandle,
			Description: fmt.Sprintf("DelRule (by Handle %d, JumpOnly): jump from %s to %s for MAC %s", ruleToDelWithHandle.Handle, parentChainName, targetPodChainName, podMac),
		})
		klog.V(5).Infof("[NFTables.EnqueueDeleteBridgeRuleJumpOnly] Enqueued OpDelRule (by Handle %d) for jump from %s to %s for MAC %s", ruleToDelWithHandle.Handle, parentChainName, targetPodChainName, podMac)
	} else {
		klog.V(4).Infof("[NFTables.EnqueueDeleteBridgeRuleJumpOnly] JUMP rule for MAC %s from %s to %s not found in cache with a valid Handle. Skipping OpDelRule enqueue for this rule.", podMac, parentChainName, targetPodChainName)
	}
}

/* EnqueueDeleteIngressDropRule enqueues the deletion of ingress drop rules.
 * If the rule is not found in the cache with a valid handle, the delete operation is skipped.
 */
func (nft *NFTables) EnqueueDeleteIngressDropRule(podMac string) {
	mac, err := net.ParseMAC(podMac)
	if err != nil {
		klog.Errorf("EnqueueDeleteIngressDropRule: Invalid MAC address %s: %v", podMac, err)
		return
	}
	tableObj := nft.GetNftTableObject(TableFilter, nftables.TableFamilyBridge)
	if tableObj == nil {
		klog.Errorf("EnqueueDeleteIngressDropRule: Table %s/%v not found.", TableFilter, nftables.TableFamilyBridge)
		return
	}

	ingressBaseChainObj := nft.FindChainByNameAndFamily(IngressChain, nftables.TableFamilyBridge)
	if ingressBaseChainObj == nil {
		klog.V(4).Infof("[NFTables.EnqueueDeleteIngressDropRule] Base chain %s not found in cache. Assuming DROP rule for MAC %s does not exist or already deleted. Skipping OpDelRule.", IngressChain, podMac)
		return
	}

	dropRuleExprsToMatch := []expr.Any{
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: DestinationHWOffset, Len: HWLength},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: mac},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}

	var ruleToDelWithHandle *nftables.Rule
	rulesInChain := nft.getRulesFromCachedChain(ingressBaseChainObj)
	if rulesInChain != nil {
		desiredSignature := utils.NormalizeExprsForComparison(dropRuleExprsToMatch)
		for _, existingRule := range rulesInChain {
			if utils.NormalizeExprsForComparison(existingRule.Exprs) == desiredSignature {
				ruleCopy := existingRule
				ruleToDelWithHandle = &ruleCopy
				klog.V(5).Infof("[NFTables.EnqueueDeleteIngressDropRule] Found DROP rule to delete by content in cache (Handle: %d) for MAC %s in %s", ruleToDelWithHandle.Handle, podMac, IngressChain)
				break
			}
		}
	}

	if ruleToDelWithHandle != nil && ruleToDelWithHandle.Handle != 0 {
		nft.EnqueueOperation(QueuedNftOperation{
			Type:        OpDelRule,
			Rule:        ruleToDelWithHandle,
			Description: fmt.Sprintf("DelRule (by Handle %d): ingress drop for MAC %s in %s", ruleToDelWithHandle.Handle, podMac, IngressChain),
		})
		klog.V(5).Infof("[NFTables.EnqueueDeleteIngressDropRule] Enqueued OpDelRule (by Handle %d) for ingress drop for MAC %s", ruleToDelWithHandle.Handle, podMac)
	} else {
		klog.V(4).Infof("[NFTables.EnqueueDeleteIngressDropRule] Ingress DROP rule for MAC %s in %s not found in cache with a valid Handle. Skipping OpDelRule enqueue.", podMac, IngressChain)
	}
}

/* EnqueueDeleteEgressDropRule enqueues the deletion of egress drop rules.
 * If the rule is not found in the cache with a valid handle, the delete operation is skipped.
 */
func (nft *NFTables) EnqueueDeleteEgressDropRule(podMac string) {
	mac, err := net.ParseMAC(podMac)
	if err != nil {
		klog.Errorf("EnqueueDeleteEgressDropRule: Invalid MAC address %s: %v", podMac, err)
		return
	}
	tableObj := nft.GetNftTableObject(TableFilter, nftables.TableFamilyBridge)
	if tableObj == nil {
		klog.Errorf("EnqueueDeleteEgressDropRule: Table %s/%v not found.", TableFilter, nftables.TableFamilyBridge)
		return
	}

	egressBaseChainObj := nft.FindChainByNameAndFamily(EgressChain, nftables.TableFamilyBridge)
	if egressBaseChainObj == nil {
		klog.V(4).Infof("[NFTables.EnqueueDeleteEgressDropRule] Base chain %s not found in cache. Assuming DROP rule for MAC %s does not exist or already deleted. Skipping OpDelRule.", EgressChain, podMac)
		return
	}

	dropRuleExprsToMatch := []expr.Any{
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: SourceHWOffset, Len: HWLength},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: mac},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}

	var ruleToDelWithHandle *nftables.Rule
	rulesInChain := nft.getRulesFromCachedChain(egressBaseChainObj)
	if rulesInChain != nil {
		desiredSignature := utils.NormalizeExprsForComparison(dropRuleExprsToMatch)
		for _, existingRule := range rulesInChain {
			if utils.NormalizeExprsForComparison(existingRule.Exprs) == desiredSignature {
				ruleCopy := existingRule
				ruleToDelWithHandle = &ruleCopy
				klog.V(5).Infof("[NFTables.EnqueueDeleteEgressDropRule] Found DROP rule to delete by content in cache (Handle: %d) for MAC %s in %s", ruleToDelWithHandle.Handle, podMac, EgressChain)
				break
			}
		}
	}

	if ruleToDelWithHandle != nil && ruleToDelWithHandle.Handle != 0 {
		nft.EnqueueOperation(QueuedNftOperation{
			Type:        OpDelRule,
			Rule:        ruleToDelWithHandle,
			Description: fmt.Sprintf("DelRule (by Handle %d): egress drop for MAC %s in %s", ruleToDelWithHandle.Handle, podMac, EgressChain),
		})
		klog.V(5).Infof("[NFTables.EnqueueDeleteEgressDropRule] Enqueued OpDelRule (by Handle %d) for egress drop for MAC %s", ruleToDelWithHandle.Handle, podMac)
	} else {
		klog.V(4).Infof("[NFTables.EnqueueDeleteEgressDropRule] Egress DROP rule for MAC %s in %s not found in cache with a valid Handle. Skipping OpDelRule enqueue.", podMac, EgressChain)
	}
}

/* EnsurePodIngressDropRule queues the creation of a DROP rule for the target MAC.
 * Attempts to delete an existing rule first to avoid duplicates.
 */
func (nft *NFTables) EnsurePodIngressDropRule(podMac string) {
	klog.V(4).Infof("[EnsurePodIngressDropRule-Enqueue] Ensuring Ingress DROP for MAC %s.", podMac)

	/* Check if the rule already exists in the cache to avoid queuing duplicates. */
	ingressBaseChainObj := nft.FindChainByNameAndFamily(IngressChain, nftables.TableFamilyBridge)
	if ingressBaseChainObj != nil {
		mac, errMac := net.ParseMAC(podMac)
		if errMac == nil {
			rulesInChain := nft.getRulesFromCachedChain(ingressBaseChainObj)
			dropRuleExprsToMatch := []expr.Any{
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: DestinationHWOffset, Len: HWLength},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: mac},
				&expr.Verdict{Kind: expr.VerdictDrop},
			}
			desiredSignature := utils.NormalizeExprsForComparison(dropRuleExprsToMatch)

			for _, existingRule := range rulesInChain {
				if utils.NormalizeExprsForComparison(existingRule.Exprs) == desiredSignature {
					klog.V(5).Infof("[EnsurePodIngressDropRule-Enqueue] Ingress DROP rule for MAC %s already exists in cache. Skipping.", podMac)
					return /* The rule already exists, it does nothing. */
				}
			}
		}
	}

	/* If the rule was not found in the cache, queue its creation. */
	klog.V(5).Infof("[EnsurePodIngressDropRule-Enqueue] Ingress DROP rule for MAC %s not found in cache. Enqueueing AddRule.", podMac)

	mac, errMac := net.ParseMAC(podMac)
	if errMac != nil {
		klog.Errorf("EnsurePodIngressDropRule: Invalid MAC %s: %v", podMac, errMac)
		return
	}
	tableObj := nft.GetNftTableObject(TableFilter, nftables.TableFamilyBridge)
	if tableObj == nil {
		klog.Errorf("EnsurePodIngressDropRule: Table %s/%v not found.", TableFilter, nftables.TableFamilyBridge)
		return
	}

	if ingressBaseChainObj == nil {
		klog.Warningf("EnsurePodIngressDropRule: Base chain %s not found in cache. Rule will be added to a new chain reference.", IngressChain)
		ingressBaseChainObj = &nftables.Chain{Name: IngressChain, Table: tableObj}
	}

	dropRuleExprs := []expr.Any{
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: DestinationHWOffset, Len: HWLength},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: mac},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
	nft.EnqueueOperation(QueuedNftOperation{
		Type:        OpAddRule,
		Rule:        &nftables.Rule{Table: tableObj, Chain: ingressBaseChainObj, Exprs: dropRuleExprs},
		Description: fmt.Sprintf("AddRule: EnsurePodIngressDropRule for MAC %s", podMac),
	})
	klog.V(5).Infof("[EnsurePodIngressDropRule-Enqueue] Enqueued OpAddRule for ingress drop for MAC %s", podMac)
}

/* EnsurePodEgressDropRule queues the creation of a DROP rule for the source MAC.
 * Attempts to delete an existing rule first to avoid duplicates.
 */
func (nft *NFTables) EnsurePodEgressDropRule(podMac string) {
	klog.V(4).Infof("[EnsurePodEgressDropRule-Enqueue] Ensuring Egress DROP for MAC %s.", podMac)

	/* Check if the rule already exists in the cache to avoid queuing duplicates. */
	egressBaseChainObj := nft.FindChainByNameAndFamily(EgressChain, nftables.TableFamilyBridge)
	if egressBaseChainObj != nil {
		mac, errMac := net.ParseMAC(podMac)
		if errMac == nil {
			rulesInChain := nft.getRulesFromCachedChain(egressBaseChainObj)
			dropRuleExprsToMatch := []expr.Any{
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: SourceHWOffset, Len: HWLength},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: mac},
				&expr.Verdict{Kind: expr.VerdictDrop},
			}
			desiredSignature := utils.NormalizeExprsForComparison(dropRuleExprsToMatch)

			for _, existingRule := range rulesInChain {
				if utils.NormalizeExprsForComparison(existingRule.Exprs) == desiredSignature {
					klog.V(5).Infof("[EnsurePodEgressDropRule-Enqueue] Egress DROP rule for MAC %s already exists in cache. Skipping.", podMac)
					return /* The rule already exists, it does nothing. */
				}
			}
		}
	}

	/* If the rule was not found in the cache, queue its creation. */
	klog.V(5).Infof("[EnsurePodEgressDropRule-Enqueue] Egress DROP rule for MAC %s not found in cache. Enqueueing AddRule.", podMac)

	mac, errMac := net.ParseMAC(podMac)
	if errMac != nil {
		klog.Errorf("EnsurePodEgressDropRule: Invalid MAC %s: %v", podMac, errMac)
		return
	}
	tableObj := nft.GetNftTableObject(TableFilter, nftables.TableFamilyBridge)
	if tableObj == nil {
		klog.Errorf("EnsurePodEgressDropRule: Table %s/%v not found.", TableFilter, nftables.TableFamilyBridge)
		return
	}

	if egressBaseChainObj == nil {
		klog.Warningf("EnsurePodEgressDropRule: Base chain %s not found in cache. Rule will be added to a new chain reference.", EgressChain)
		egressBaseChainObj = &nftables.Chain{Name: EgressChain, Table: tableObj}
	}

	dropRuleExprs := []expr.Any{
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: SourceHWOffset, Len: HWLength},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: mac},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
	nft.EnqueueOperation(QueuedNftOperation{
		Type:        OpAddRule,
		Rule:        &nftables.Rule{Table: tableObj, Chain: egressBaseChainObj, Exprs: dropRuleExprs},
		Description: fmt.Sprintf("AddRule: EnsurePodEgressDropRule for MAC %s", podMac),
	})
	klog.V(5).Infof("[EnsurePodEgressDropRule-Enqueue] Enqueued OpAddRule for egress drop for MAC %s", podMac)
}

/* EnqueueCreateBridgeRuleJumpOnly enqueues only the JUMP rule.
 * Checks if an identical rule already exists in the cache to avoid duplication.
 */
func (nft *NFTables) EnqueueCreateBridgeRuleJumpOnly(baseChainName, targetPodChainName, podMac string, hwOffsetConstant uint32) {
	mac, errMac := net.ParseMAC(podMac)
	if errMac != nil {
		klog.Errorf("EnqueueCreateBridgeRuleJumpOnly: Invalid MAC %s: %v", podMac, errMac)
		return
	}

	tableObj := nft.GetNftTableObject(TableFilter, nftables.TableFamilyBridge)
	if tableObj == nil {
		klog.Errorf("EnqueueCreateBridgeRuleJumpOnly: Table %s/%v not found for base chain %s", TableFilter, nftables.TableFamilyBridge, baseChainName)
		return
	}

	baseChainObjFromCache := nft.FindChainByNameAndFamily(baseChainName, nftables.TableFamilyBridge)
	if baseChainObjFromCache == nil {
		klog.Warningf("EnqueueCreateBridgeRuleJumpOnly: Base chain %s not found in cache. Will proceed to add JUMP rule to a new chain reference.", baseChainName)
		baseChainObjFromCache = &nftables.Chain{Name: baseChainName, Table: tableObj}
	}

	desiredJumpRuleExprs := []expr.Any{
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: hwOffsetConstant, Len: HWLength},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: mac},
		&expr.Verdict{Kind: expr.VerdictJump, Chain: targetPodChainName},
	}
	desiredJumpRuleSignature := utils.NormalizeExprsForComparison(desiredJumpRuleExprs)
	jumpRuleExists := false

	rulesInBaseChain := nft.getRulesFromCachedChain(baseChainObjFromCache)

	for _, existingRule := range rulesInBaseChain {
		isPotentiallySameRule := false
		if len(existingRule.Exprs) == 3 { /* We expect 3 expressions for this jump rule */
			if p, pOk := existingRule.Exprs[0].(*expr.Payload); pOk {
				if c, cOk := existingRule.Exprs[1].(*expr.Cmp); cOk {
					if v, vOk := existingRule.Exprs[2].(*expr.Verdict); vOk {
						if p.Base == expr.PayloadBaseLLHeader && p.Offset == hwOffsetConstant &&
							bytes.Equal(c.Data, mac) &&
							v.Kind == expr.VerdictJump && v.Chain == targetPodChainName {
							isPotentiallySameRule = true
						}
					}
				}
			}
		}

		if isPotentiallySameRule {
			if utils.NormalizeExprsForComparison(existingRule.Exprs) == desiredJumpRuleSignature {
				jumpRuleExists = true
				klog.V(5).Infof("[NFTables.EnqueueCreateBridgeRuleJumpOnly] Identical JUMP rule for MAC %s to %s already exists in cache for %s. Skipping AddRule.", podMac, targetPodChainName, baseChainName)
				break
			}
		}
	}

	if !jumpRuleExists {
		nft.EnqueueOperation(QueuedNftOperation{
			Type:        OpAddRule,
			Rule:        &nftables.Rule{Table: tableObj, Chain: baseChainObjFromCache, Exprs: desiredJumpRuleExprs},
			Description: fmt.Sprintf("AddRule (JumpOnly): jump to %s for MAC %s in %s", targetPodChainName, podMac, baseChainName),
		})
		klog.V(4).Infof("[NFTables.EnqueueCreateBridgeRuleJumpOnly] Enqueued AddRule for JUMP to %s for MAC %s in %s.", targetPodChainName, podMac, baseChainName)
	}
}
