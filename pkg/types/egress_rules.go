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

/* resolveEgressPorts processes the policy ports, resolving named ports against the source pod's containers.
 * It returns separate slices for resolved TCP and UDP port numbers.
 */
func resolveEgressPorts(policyPorts []multiv1beta1.MultiNetworkPolicyPort, sourcePod *v1.Pod) ([]uint16, []uint16) {
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
			/* For Egress, named port resolution is against the source pod's containers. */
			for _, container := range sourcePod.Spec.Containers {
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
				klog.Warningf("Named port '%s' (protocol %s) for egress rule not found in source pod %s/%s containers. Skipping.", portName, protocolName, sourcePod.Namespace, sourcePod.Name)
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

/* buildEgressExpressions constructs the common expression parts for an egress rule. */
func (nft *NFTables) buildEgressExpressions(ipSet *nftables.Set, cidr *string, portSet *nftables.Set, protoName string) []expr.Any {
	var exprs []expr.Any
	exprs = append(exprs, nft.buildExprCheckProtoIP()...)

	if ipSet != nil {
		exprs = append(exprs, nft.buildExprDestinationIP(ipSet)...)
	} else if cidr != nil {
		maskExprs := nft.buildExprDestinationMask(*cidr)
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

/* renderEgressRuleForProtocol generates and enqueues nftables rules for a specific protocol (TCP or UDP). */
func (nft *NFTables) renderEgressRuleForProtocol(chain *nftables.Chain, portSet *nftables.Set, ipSet *nftables.Set, hasValidSingleIPs bool, hwSet *nftables.Set, resolvedMacs []string, cidrList []string, allowAnyDest bool, ruleIndex int, protoName string) int {
	renderedCount := 0
	if portSet == nil {
		return 0
	}

	/* Rule for IP set */
	if ipSet != nil && hasValidSingleIPs {
		exprs := nft.buildEgressExpressions(ipSet, nil, portSet, protoName)
		nft.EnqueueOperation(QueuedNftOperation{Type: OpAddRule, Rule: &nftables.Rule{Table: chain.Table, Chain: chain, Exprs: exprs}, Description: fmt.Sprintf("AddRule Egress: %s/IP (Dst Set: %s, Port Set: %s) for chain %s, MNP ruleIdx %d", protoName, ipSet.Name, portSet.Name, chain.Name, ruleIndex)})
		renderedCount++
	}

	/* Rules for CIDR list */
	for _, cidr := range cidrList {
		exprs := nft.buildEgressExpressions(nil, &cidr, portSet, protoName)
		if exprs != nil {
			nft.EnqueueOperation(QueuedNftOperation{Type: OpAddRule, Rule: &nftables.Rule{Table: chain.Table, Chain: chain, Exprs: exprs}, Description: fmt.Sprintf("AddRule Egress: %s/IP (Dst CIDR %s, Port Set: %s) for chain %s, MNP ruleIdx %d", protoName, cidr, portSet.Name, chain.Name, ruleIndex)})
			renderedCount++
		}
	}

	/* Rule for MAC set */
	if hwSet != nil && len(resolvedMacs) > 0 {
		exprs := nft.buildEgressExpressions(nil, nil, portSet, protoName)
		exprs = append(nft.buildExprDestinationHW(hwSet), exprs...) // Prepend HW check
		nft.EnqueueOperation(QueuedNftOperation{Type: OpAddRule, Rule: &nftables.Rule{Table: chain.Table, Chain: chain, Exprs: exprs}, Description: fmt.Sprintf("AddRule Egress: %s/HW (Dst Set: %s, Port Set: %s) for chain %s, MNP ruleIdx %d", protoName, hwSet.Name, portSet.Name, chain.Name, ruleIndex)})
		renderedCount++
	}

	/* Rule for allowing to any destination if specified */
	if allowAnyDest {
		exprs := nft.buildEgressExpressions(nil, nil, portSet, protoName)
		nft.EnqueueOperation(QueuedNftOperation{Type: OpAddRule, Rule: &nftables.Rule{Table: chain.Table, Chain: chain, Exprs: exprs}, Description: fmt.Sprintf("AddRule Egress: %s (Any Destination, Port Set: %s) for chain %s, MNP ruleIdx %d", protoName, portSet.Name, chain.Name, ruleIndex)})
		renderedCount++
	}

	return renderedCount
}

/* RenderEgressRules queues nftables operations for egress rules
 * for a SINGLE MNP Egress rule (an item from the MNP.Spec.Egress slice).
 * RETURNS: The number of ACCEPT rules actually queued by this call.
 */
func (nft *NFTables) RenderEgressRules(
	chainNameSuffix string,
	ruleIndex int, /* Egress rule index within MNP.Spec.Egress       */
	resolvedIPBlocks []string, /* Resolved Destination IPs for THIS Egress Rule  */
	resolvedMacAddresses []string, /* Resolved Destination MACs for THIS Egress Rule */
	policyPorts []multiv1beta1.MultiNetworkPolicyPort, /* Destination Ports for THIS Egress rule         */
	sourcePod *v1.Pod, /* The Pod from which the traffic is egressing.   */
) int {
	fullChainName := EgressChain + "_" + chainNameSuffix
	renderedRuleCount := 0 /* Counter for actually created ACCEPT rules */

	klog.V(4).Infof("[RenderEgressRules-Enqueue] For chain %s (suffix: %s), MNP Rule Index %d, sourcePod %s/%s", fullChainName, chainNameSuffix, ruleIndex, sourcePod.Namespace, sourcePod.Name)
	klog.V(5).Infof("  Policy Ports for this rule: %+v", policyPorts)
	klog.V(5).Infof("  Resolved Destination IPBlocks for this rule: %v", resolvedIPBlocks)
	klog.V(5).Infof("  Resolved Destination MAC Addresses for this rule: %v", resolvedMacAddresses)

	tcpPorts, udpPorts := resolveEgressPorts(policyPorts, sourcePod)
	klog.V(5).Infof("[RenderEgressRules-Enqueue] Chain %s, MNP RuleIdx %d: Parsed TCP Ports for Egress Destination: %v, UDP Ports for Egress Destination: %v", fullChainName, ruleIndex, tcpPorts, udpPorts)

	if len(policyPorts) > 0 && (len(tcpPorts) == 0 && len(udpPorts) == 0) {
		klog.V(4).Infof("[RenderEgressRules-Enqueue] Chain %s, MNP RuleIdx %d: PolicyPorts defined but no valid TCP/UDP ports were resolved for egress destination. No nftables rules will be generated for this specific egress rule entry.", fullChainName, ruleIndex)
		return 0
	}

	targetChainObj := nft.GetNftChainObject(fullChainName, TableFilter, nftables.TableFamilyBridge)
	if targetChainObj == nil {
		klog.Errorf("[RenderEgressRules-Enqueue] CRITICAL: GetNftChainObject returned nil for %s. Aborting rule rendering for MNP rule index %d.", fullChainName, ruleIndex)
		return 0
	}
	klog.V(6).Infof("[RenderEgressRules-Enqueue] Using Table '%s', Chain '%s' for enqueuing rules for MNP rule index %d.", targetChainObj.Table.Name, targetChainObj.Name, ruleIndex)

	isToSectionEmpty := len(resolvedIPBlocks) == 0 && len(resolvedMacAddresses) == 0
	isPortsSectionEmpty := len(policyPorts) == 0

	if isToSectionEmpty && isPortsSectionEmpty {
		klog.V(3).Infof("[RenderEgressRules-Enqueue] Chain %s, MNP RuleIdx %d: Enqueueing OpAddRule to accept all egress traffic (both 'to' and 'ports' are empty for this rule entry).", fullChainName, ruleIndex)
		acceptAllRule := &nftables.Rule{
			Table: targetChainObj.Table, Chain: targetChainObj,
			Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
		}
		nft.EnqueueOperation(QueuedNftOperation{Type: OpAddRule, Rule: acceptAllRule, Description: fmt.Sprintf("AddRule Egress: Accept all for chain %s, MNP ruleIdx %d", fullChainName, ruleIndex)})
		renderedRuleCount++
		return renderedRuleCount
	}

	commonDstIPSet, commonDstCidrList, hasValidSingleIPs := nft.buildIPSet(chainNameSuffix, string(NftRuleDirectionEgress), ruleIndex, NftSetTypeDstIP, resolvedIPBlocks)

	commonDstHWSet := nft.buildHWSet(chainNameSuffix, string(NftRuleDirectionEgress), ruleIndex, NftSetTypeDstMAC, resolvedMacAddresses)

	allowToAnyDestinationForPorts := isToSectionEmpty && !isPortsSectionEmpty

	if len(tcpPorts) > 0 {
		thisTCPSet := nft.buildTCPPortSet(chainNameSuffix, string(NftRuleDirectionEgress), ruleIndex, tcpPorts)
		renderedRuleCount += nft.renderEgressRuleForProtocol(targetChainObj, thisTCPSet, commonDstIPSet, hasValidSingleIPs, commonDstHWSet, resolvedMacAddresses, commonDstCidrList, allowToAnyDestinationForPorts, ruleIndex, TCPProto)
	}

	if len(udpPorts) > 0 {
		thisUDPSet := nft.buildUDPPortSet(chainNameSuffix, string(NftRuleDirectionEgress), ruleIndex, udpPorts)
		renderedRuleCount += nft.renderEgressRuleForProtocol(targetChainObj, thisUDPSet, commonDstIPSet, hasValidSingleIPs, commonDstHWSet, resolvedMacAddresses, commonDstCidrList, allowToAnyDestinationForPorts, ruleIndex, UDPProto)
	}

	if renderedRuleCount == 0 && !isToSectionEmpty && !isPortsSectionEmpty {
		klog.V(3).Infof("[RenderEgressRules-Enqueue] Chain %s, MNP RuleIdx %d: No valid ACCEPT rules were generated for this egress entry despite peers/ports being specified (likely all invalid or no matching protocol rules). Effective policy for this entry is DENY.", fullChainName, ruleIndex)
	}

	klog.V(4).Infof("[RenderEgressRules-Enqueue] Finished for chain %s, MNP RuleIdx %d. Enqueued %d nftables ACCEPT rule(s) for this specific 'to' entry.", fullChainName, ruleIndex, renderedRuleCount)
	return renderedRuleCount
}
