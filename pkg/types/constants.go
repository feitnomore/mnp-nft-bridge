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

type NftSetType string
type NftRuleDirection string

const (
	setSize    = 16
	singleMask = "255.255.255.255"

	/* CNI Drivers */
	CNIDriverBridge = "bridge"

	/* Protocols */
	TCPProto     = "TCP"
	UDPProto     = "UDP"
	DefaultProto = "TCP"

	/* Chains */
	IngressChain     = "KUBE_MULTI_INGRESS"
	EgressChain      = "KUBE_MULTI_EGRESS"
	PreroutingChain  = "prerouting"  /* Used as a hook for EgressChain in the bridge family                   */
	PostroutingChain = "postrouting" /* Generally not used directly by the controller for MultiNetworkPolicy  */
	IngressChainType = "ingress"     /* Used to identify the type of chain/rule                               */
	EgressChainType  = "egress"      /* Used to identify the type of chain/rule                               */

	/* Tables */
	TableFilter = "filter"

	/* Offsets and Sizes */
	SourceIPOffset        = 12
	DestinationIPOffset   = 16
	IPLength              = 4
	SourceHWOffset        = 6
	DestinationHWOffset   = 0
	HWLength              = 6
	SourcePortOffset      = 0 /* For incoming packets, the sender's source port. For outgoing packets, the local pod's source port.               */
	DestinationPortOffset = 2 /* For incoming packets, the local pod's destination port. For outgoing packets, the remote pod's destination port. */
	PortLength            = 2

	/* Set Types */
	NftSetTypeSrcIP   NftSetType = "src-ip"   /* NftSetTypeSrcIP indicates a set containing source IP addresses.        */
	NftSetTypeSrcMAC  NftSetType = "src-mac"  /* NftSetTypeSrcMAC indicates a set containing source MAC addresses.      */
	NftSetTypeDstIP   NftSetType = "dst-ip"   /* NftSetTypeDstIP indicates a set containing destination IP addresses.   */
	NftSetTypeDstMAC  NftSetType = "dst-mac"  /* NftSetTypeDstMAC indicates a set containing destination MAC addresses. */
	NftSetTypeTCPPort NftSetType = "tcp-port" /* NftSetTypeTCPPort indicates a set containing TCP ports.                */
	NftSetTypeUDPPort NftSetType = "udp-port" /* NftSetTypeUDPPort indicates a set containing UDP ports.                */

	/* Rule Direction */
	NftRuleDirectionIngress NftRuleDirection = "ingress" /* NftRuleDirectionIngress represents the ingress direction. */
	NftRuleDirectionEgress  NftRuleDirection = "egress"  /* NftRuleDirectionEgress represents the egress direction.   */

	DescAllTCPPorts = "all TCP ports"
	DescAllUDPPorts = "all UDP ports"

	PolicyForAnnotation = "k8s.v1.cni.cncf.io/policy-for"
)
