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
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/klog/v2"
)

/* resolveIngressPorts processes the policy ports, resolving named ports against the target pod's containers. */
func resolveIngressPorts(policyPorts []multiv1beta1.MultiNetworkPolicyPort, targetPod *v1.Pod) ([]uint16, []uint16) {
	var tcpPorts, udpPorts []uint16

	for _, policyPort := range policyPorts {
		var portNumber int32
		protocolName := DefaultProto /* Assume TCP if not specified */
		if policyPort.Protocol != nil {
			protocolName = string(*policyPort.Protocol)
		}

		if policyPort.Port.Type == intstr.Int {
			portNumber = policyPort.Port.IntVal
		} else if policyPort.Port.Type == intstr.String {
			portName := policyPort.Port.StrVal
			found := false
			for _, container := range targetPod.Spec.Containers {
				for _, cPort := range container.Ports {
					if cPort.Name == portName {
						containerProto := TCPProto
						if cPort.Protocol != "" {
							containerProto = string(cPort.Protocol)
						}
						if strings.EqualFold(protocolName, containerProto) {
							portNumber = cPort.ContainerPort
							found = true
							break
						}
					}
				}
				if found {
					break
				}
			}
			if !found {
				klog.Warningf("Named port '%s' (protocol %s) not found in target pod %s/%s containers. Skipping.", portName, protocolName, targetPod.Namespace, targetPod.Name)
				continue
			}
		}

		if portNumber > 0 && portNumber <= 65535 {
			switch strings.ToUpper(protocolName) {
			case TCPProto:
				tcpPorts = append(tcpPorts, uint16(portNumber))
			case UDPProto:
				udpPorts = append(udpPorts, uint16(portNumber))
			}
		}
	}
	return tcpPorts, udpPorts
}

/* buildIngressExpressions constructs the common expression parts for an ingress rule. */
func (nft *NFTables) buildIngressExpressions(ipSet *nftables.Set, cidr *string, portSet *nftables.Set, protoName string) []expr.Any {
	var exprs []expr.Any
	exprs = append(exprs, nft.buildExprCheckProtoIP()...)

	if ipSet != nil {
		exprs = append(exprs, nft.buildExprSourceIP(ipSet)...)
	} else if cidr != nil {
		maskExprs := nft.buildExprSourceMask(*cidr)
		if maskExprs == nil {
			return nil /* Invalid CIDR, skip rule */
		}
		exprs = append(exprs, maskExprs...)
	}

	switch protoName {
	case TCPProto:
		exprs = append(exprs, nft.buildExprTCPPorts(portSet)...)
	case UDPProto:
		exprs = append(exprs, nft.buildExprUDPPorts(portSet)...)
	}

	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
	return exprs
}

/* renderIngressRuleForProtocol generates and enqueues nftables rules for a specific protocol (TCP or UDP). */
func (nft *NFTables) renderIngressRuleForProtocol(chain *nftables.Chain, portSet *nftables.Set, ipSet *nftables.Set, hasValidSingleIPs bool, hwSet *nftables.Set, resolvedMacs []string, cidrList []string, allowAnySource bool, ruleIndex int, protoName string) int {
	renderedCount := 0
	if portSet == nil {
		return 0
	}

	/* Rule for IP set */
	if ipSet != nil && hasValidSingleIPs {
		exprs := nft.buildIngressExpressions(ipSet, nil, portSet, protoName)
		nft.EnqueueOperation(QueuedNftOperation{Type: OpAddRule, Rule: &nftables.Rule{Table: chain.Table, Chain: chain, Exprs: exprs}, Description: fmt.Sprintf("AddRule Ingress: %s/IP (Src Set: %s, Port Set: %s) for chain %s, MNP ruleIdx %d", protoName, ipSet.Name, portSet.Name, chain.Name, ruleIndex)})
		renderedCount++
	}

	/* Rules for CIDR list */
	for _, cidr := range cidrList {
		exprs := nft.buildIngressExpressions(nil, &cidr, portSet, protoName)
		if exprs != nil {
			nft.EnqueueOperation(QueuedNftOperation{Type: OpAddRule, Rule: &nftables.Rule{Table: chain.Table, Chain: chain, Exprs: exprs}, Description: fmt.Sprintf("AddRule Ingress: %s/IP (Src CIDR %s, Port Set: %s) for chain %s, MNP ruleIdx %d", protoName, cidr, portSet.Name, chain.Name, ruleIndex)})
			renderedCount++
		}
	}

	/* Rule for MAC set */
	if hwSet != nil && len(resolvedMacs) > 0 {
		exprs := nft.buildIngressExpressions(nil, nil, portSet, protoName)
		exprs = append(nft.buildExprSourceHW(hwSet), exprs...) // Prepend HW check
		nft.EnqueueOperation(QueuedNftOperation{Type: OpAddRule, Rule: &nftables.Rule{Table: chain.Table, Chain: chain, Exprs: exprs}, Description: fmt.Sprintf("AddRule Ingress: %s/HW (Src Set: %s, Port Set: %s) for chain %s, MNP ruleIdx %d", protoName, hwSet.Name, portSet.Name, chain.Name, ruleIndex)})
		renderedCount++
	}

	/* Rule for allowing from any source if specified */
	if allowAnySource {
		exprs := nft.buildIngressExpressions(nil, nil, portSet, protoName)
		nft.EnqueueOperation(QueuedNftOperation{Type: OpAddRule, Rule: &nftables.Rule{Table: chain.Table, Chain: chain, Exprs: exprs}, Description: fmt.Sprintf("AddRule Ingress: %s (Any Source, Port Set: %s) for chain %s, MNP ruleIdx %d", protoName, portSet.Name, chain.Name, ruleIndex)})
		renderedCount++
	}

	return renderedCount
}

/* RenderIngressRules queues nftables operations for ingress rules
 * for a SINGLE MNP Ingress rule (an item from the MNP.Spec.Ingress slice).
 * RETURNS: The number of ACCEPT rules actually queued by this call.
 */
func (nft *NFTables) RenderIngressRules(
	chainNameSuffix string,
	ruleIndex int, /* Index of the Ingress rule within MNP.Spec.Ingress  */
	resolvedIPBlocks []string, /* Source IPs resolved for THIS Ingress rule          */
	resolvedMacAddresses []string, /* Resolved Source MACs for THIS Ingress rule         */
	policyPorts []multiv1beta1.MultiNetworkPolicyPort, /* Destination Ports on the Pod for THIS Ingress rule */
	originalFromRule []multiv1beta1.MultiNetworkPolicyPeer,
	targetPod *v1.Pod,
) int {
	fullChainName := IngressChain + "_" + chainNameSuffix
	renderedRuleCount := 0 /* Counter for effectively created ACCEPT rules */

	klog.V(4).Infof("[RenderIngressRules-Enqueue] For chain %s (suffix: %s), MNP Rule Index %d, pod %s/%s", fullChainName, chainNameSuffix, ruleIndex, targetPod.Namespace, targetPod.Name)
	klog.V(5).Infof("  Policy Ports for this rule: %+v", policyPorts)
	klog.V(5).Infof("  Resolved Source IPBlocks for this rule: %v", resolvedIPBlocks)
	klog.V(5).Infof("  Resolved Source MAC Addresses for this rule: %v", resolvedMacAddresses)

	tcpPorts, udpPorts := resolveIngressPorts(policyPorts, targetPod)
	klog.V(5).Infof("[RenderIngressRules-Enqueue] Chain %s, MNP RuleIdx %d: Parsed TCP Ports for Ingress Target: %v, UDP Ports for Ingress Target: %v", fullChainName, ruleIndex, tcpPorts, udpPorts)

	/* If policyPorts was specified in the MNP, but no valid ports (TCP or UDP) were resolved,
	 * then this "from" rule should not allow traffic, even if there are valid sources.
	 */
	if len(policyPorts) > 0 && (len(tcpPorts) == 0 && len(udpPorts) == 0) {
		klog.V(4).Infof("[RenderIngressRules-Enqueue] Chain %s, MNP RuleIdx %d: PolicyPorts defined but no valid TCP/UDP ports were resolved for ingress target. No nftables rules will be generated for this specific ingress rule entry.", fullChainName, ruleIndex)
		return 0 /* No ACCEPT rules will be generated */
	}

	targetChainObj := nft.GetNftChainObject(fullChainName, TableFilter, nftables.TableFamilyBridge)
	if targetChainObj == nil {
		klog.Errorf("[RenderIngressRules-Enqueue] CRITICAL: GetNftChainObject returned nil for %s. Aborting rule rendering for MNP rule index %d.", fullChainName, ruleIndex)
		return 0
	}
	klog.V(6).Infof("[RenderIngressRules-Enqueue] Using Table '%s', Chain '%s' for enqueuing rules for MNP rule index %d.", targetChainObj.Table.Name, targetChainObj.Name, ruleIndex)

	/* Case 1: "from" and "ports" sections are BOTH empty in MNP. This means "allow everything from everyone". */
	isFromSectionEmptyInSpec := len(originalFromRule) == 0
	isPortsSectionEmpty := len(policyPorts) == 0

	if isFromSectionEmptyInSpec && isPortsSectionEmpty {
		klog.V(3).Infof("[RenderIngressRules-Enqueue] Chain %s, MNP RuleIdx %d: Enqueueing OpAddRule to accept all ingress traffic (both 'from' and 'ports' are empty for this rule entry).", fullChainName, ruleIndex)
		acceptAllRule := &nftables.Rule{
			Table: targetChainObj.Table, Chain: targetChainObj,
			Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
		}
		nft.EnqueueOperation(QueuedNftOperation{Type: OpAddRule, Rule: acceptAllRule, Description: fmt.Sprintf("AddRule Ingress: Accept all for chain %s, MNP ruleIdx %d", fullChainName, ruleIndex)})
		renderedRuleCount++
		return renderedRuleCount
	}

	commonSrcIPSet, commonCidrList, hasValidSingleIPsInSet := nft.buildIPSet(chainNameSuffix, string(NftRuleDirectionIngress), ruleIndex, NftSetTypeSrcIP, resolvedIPBlocks)

	commonSrcHWSet := nft.buildHWSet(chainNameSuffix, string(NftRuleDirectionIngress), ruleIndex, NftSetTypeSrcMAC, resolvedMacAddresses)

	allowFromAnySourceForPorts := isFromSectionEmptyInSpec && !isPortsSectionEmpty

	if len(tcpPorts) > 0 {
		thisTCPSet := nft.buildTCPPortSet(chainNameSuffix, string(NftRuleDirectionIngress), ruleIndex, tcpPorts)
		renderedRuleCount += nft.renderIngressRuleForProtocol(targetChainObj, thisTCPSet, commonSrcIPSet, hasValidSingleIPsInSet, commonSrcHWSet, resolvedMacAddresses, commonCidrList, allowFromAnySourceForPorts, ruleIndex, TCPProto)
	}

	if len(udpPorts) > 0 {
		thisUDPSet := nft.buildUDPPortSet(chainNameSuffix, string(NftRuleDirectionIngress), ruleIndex, udpPorts)
		renderedRuleCount += nft.renderIngressRuleForProtocol(targetChainObj, thisUDPSet, commonSrcIPSet, hasValidSingleIPsInSet, commonSrcHWSet, resolvedMacAddresses, commonCidrList, allowFromAnySourceForPorts, ruleIndex, UDPProto)
	}

	/* If, after processing TCP and UDP, no ACCEPT rules were generated (renderedRuleCount == 0),
	 * but the "from" rule in the MNP had peers or ports (i.e., it wasn't an empty "allow all" rule),
	 * this means that all the specified peers/ports were invalid or resulted in no rules.
	 * In this case, this specific "from" entry doesn't allow traffic.
	 */
	if renderedRuleCount == 0 && !isFromSectionEmptyInSpec && !isPortsSectionEmpty {
		klog.V(3).Infof("[RenderIngressRules-Enqueue] Chain %s, MNP RuleIdx %d: No valid ACCEPT rules were generated for this ingress entry despite peers/ports being specified (likely all invalid or no matching protocol rules). Effective policy for this entry is DENY.", fullChainName, ruleIndex)
	}

	klog.V(4).Infof("[RenderIngressRules-Enqueue] Finished for chain %s, MNP RuleIdx %d. Enqueued %d nftables ACCEPT rule(s) for this specific 'from' entry.", fullChainName, ruleIndex, renderedRuleCount)
	return renderedRuleCount
}
