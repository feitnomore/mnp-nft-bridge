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
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/* Helper to create an NFTables instance for egress_rules tests. */
func newTestNFTablesForEgressRules(targetChainFullName string) *NFTables {
	nft := NewNftTables()
	if nft.table == nil {
		nft.table = make([]internalTable, 0)
	}
	if nft.InternalQueue == nil {
		nft.InternalQueue = make([]QueuedNftOperation, 0)
	}

	mockTable := &nftables.Table{Name: TableFilter, Family: nftables.TableFamilyBridge}
	nft.table = append(nft.table, internalTable{
		name:   TableFilter,
		table:  mockTable,
		family: nftables.TableFamilyBridge,
	})
	if targetChainFullName != "" {
		nft.table = append(nft.table, internalTable{
			name:   targetChainFullName,
			chain:  &nftables.Chain{Name: targetChainFullName, Table: mockTable, Type: nftables.ChainTypeFilter},
			table:  mockTable,
			family: nftables.TableFamilyBridge,
			kind:   nftables.ChainTypeFilter,
		})
	}
	return nft
}

func findAddRuleOperationsEgress(t *testing.T, queue []QueuedNftOperation, targetChainName string) []*nftables.Rule {
	t.Helper()
	var rules []*nftables.Rule
	for i := range queue {
		op := &queue[i]
		if op.Type == OpAddRule && op.Rule != nil && op.Rule.Chain != nil && op.Rule.Chain.Name == targetChainName {
			rules = append(rules, op.Rule)
		}
	}
	return rules
}

func TestRenderEgressRules_BasicIPBlockAndPort(t *testing.T) {
	chainSuffix := "egressbasic"
	targetChainFullName := EgressChain + "_" + chainSuffix
	nft := newTestNFTablesForEgressRules(targetChainFullName)

	sourcePod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "sourcepod", Namespace: "default"},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{Ports: []v1.ContainerPort{{Name: "api", ContainerPort: 8080, Protocol: v1.ProtocolTCP}}},
			},
		},
	}
	policyPorts := []multiv1beta1.MultiNetworkPolicyPort{
		{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 443}, Protocol: ptr.To(v1.ProtocolTCP)},
	}
	resolvedDstIPs := []string{"203.0.113.10/32"}
	resolvedDstMACs := []string{}

	renderedCount := nft.RenderEgressRules(chainSuffix, 0, resolvedDstIPs, resolvedDstMACs, policyPorts, sourcePod)
	assert.Equal(t, 1, renderedCount, "Expected 1 accept rule to be rendered")

	require.Len(t, nft.InternalQueue, 7, "Expected 7 operations in queue")

	ipFlushOp := nft.InternalQueue[0]
	require.Equal(t, OpFlushSet, ipFlushOp.Type)
	assert.True(t, strings.HasPrefix(ipFlushOp.Set.Name, "mnp-dst-ip-"), "DstIP FlushSet name prefix mismatch")

	ipSetOp := nft.InternalQueue[1]
	require.Equal(t, OpAddSet, ipSetOp.Type)
	require.NotNil(t, ipSetOp.Set)
	assert.True(t, strings.HasPrefix(ipSetOp.Set.Name, "mnp-dst-ip-"), "DstIP AddSet name prefix mismatch")
	assert.Equal(t, nftables.TypeIPAddr, ipSetOp.Set.KeyType)
	require.Len(t, ipSetOp.SetElements, 1)
	assert.True(t, bytes.Equal(net.ParseIP("203.0.113.10").To4(), ipSetOp.SetElements[0].Key), "DstIP element mismatch")

	macFlushOp := nft.InternalQueue[2]
	require.Equal(t, OpFlushSet, macFlushOp.Type)
	assert.True(t, strings.HasPrefix(macFlushOp.Set.Name, "mnp-dst-mac-"), "DstMAC FlushSet name prefix mismatch")

	macSetOp := nft.InternalQueue[3]
	require.Equal(t, OpAddSet, macSetOp.Type)
	assert.True(t, strings.HasPrefix(macSetOp.Set.Name, "mnp-dst-mac-"), "DstMAC AddSet name prefix mismatch")
	assert.Empty(t, macSetOp.SetElements, "DstMAC set should be empty")

	portFlushOp := nft.InternalQueue[4]
	require.Equal(t, OpFlushSet, portFlushOp.Type)
	assert.True(t, strings.HasPrefix(portFlushOp.Set.Name, "mnp-tcp-port-"), "TCP Port FlushSet name prefix mismatch")

	portSetOp := nft.InternalQueue[5]
	require.Equal(t, OpAddSet, portSetOp.Type)
	assert.True(t, strings.HasPrefix(portSetOp.Set.Name, "mnp-tcp-port-"), "TCP Port AddSet name prefix mismatch")
	require.Len(t, portSetOp.SetElements, 1)
	assert.Equal(t, binaryutil.BigEndian.PutUint16(443), portSetOp.SetElements[0].Key)

	addRuleOp := nft.InternalQueue[6]
	require.Equal(t, OpAddRule, addRuleOp.Type)
	require.NotNil(t, addRuleOp.Rule)
	assert.Equal(t, targetChainFullName, addRuleOp.Rule.Chain.Name)

	foundDstIPLookup := false
	foundPortLookup := false
	foundAccept := false
	for _, exprAny := range addRuleOp.Rule.Exprs {
		if lookup, ok := exprAny.(*expr.Lookup); ok {
			if strings.HasPrefix(lookup.SetName, "mnp-dst-ip-") {
				foundDstIPLookup = true
			}
			if strings.HasPrefix(lookup.SetName, "mnp-tcp-port-") {
				foundPortLookup = true
			}
		}
		if verdict, ok := exprAny.(*expr.Verdict); ok && verdict.Kind == expr.VerdictAccept {
			foundAccept = true
		}
	}
	assert.True(t, foundDstIPLookup, "Rule should contain lookup for DstIP set")
	assert.True(t, foundPortLookup, "Rule should contain lookup for Port set")
	assert.True(t, foundAccept, "Rule should contain accept verdict")
}

func TestRenderEgressRules_NamedPortResolutionAgainstSourcePod(t *testing.T) {
	chainSuffix := "egressnamed"
	targetChainFullName := EgressChain + "_" + chainSuffix
	nft := newTestNFTablesForEgressRules(targetChainFullName)

	sourcePod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "sourcepod", Namespace: "default"},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name: "app",
					Ports: []v1.ContainerPort{
						{Name: "dest-http", ContainerPort: 80, Protocol: v1.ProtocolTCP},
						{Name: "dest-https", ContainerPort: 443, Protocol: v1.ProtocolTCP},
						{Name: "dest-dns-udp", ContainerPort: 53, Protocol: v1.ProtocolUDP},
					},
				},
			},
		},
	}
	policyPorts := []multiv1beta1.MultiNetworkPolicyPort{
		{Port: &intstr.IntOrString{Type: intstr.String, StrVal: "dest-http"}, Protocol: ptr.To(v1.ProtocolTCP)},
		{Port: &intstr.IntOrString{Type: intstr.String, StrVal: "dest-dns-udp"}, Protocol: ptr.To(v1.ProtocolUDP)},
		{Port: &intstr.IntOrString{Type: intstr.String, StrVal: "nonexistent-in-source"}, Protocol: ptr.To(v1.ProtocolTCP)},
	}
	resolvedDstIPs := []string{"203.0.113.20/32"}
	resolvedDstMACs := []string{}

	renderedCount := nft.RenderEgressRules(chainSuffix, 0, resolvedDstIPs, resolvedDstMACs, policyPorts, sourcePod)
	assert.Equal(t, 2, renderedCount, "Expected 2 accept rules (1 for TCP, 1 for UDP)")

	require.Len(t, nft.InternalQueue, 10, "Expected 10 operations in queue")

	var tcpPortSetOp *QueuedNftOperation
	var tcpPortElements []nftables.SetElement
	for _, op := range nft.InternalQueue {
		if op.Type == OpAddSet && op.Set != nil && strings.HasPrefix(op.Set.Name, "mnp-tcp-port-") {
			tcpPortSetOp = &op
			tcpPortElements = op.SetElements
			break
		}
	}
	require.NotNil(t, tcpPortSetOp, "TCP Port Set Add operation not found")
	require.Len(t, tcpPortElements, 1, "Expected 1 TCP port in the set")
	assert.Equal(t, binaryutil.BigEndian.PutUint16(80), tcpPortElements[0].Key)

	var udpPortSetOp *QueuedNftOperation
	var udpPortElements []nftables.SetElement
	for _, op := range nft.InternalQueue {
		if op.Type == OpAddSet && op.Set != nil && strings.HasPrefix(op.Set.Name, "mnp-udp-port-") {
			udpPortSetOp = &op
			udpPortElements = op.SetElements
			break
		}
	}
	require.NotNil(t, udpPortSetOp, "UDP Port Set Add operation not found")
	require.Len(t, udpPortElements, 1, "Expected 1 UDP port in the set")
	assert.Equal(t, binaryutil.BigEndian.PutUint16(53), udpPortElements[0].Key)
}

func TestRenderEgressRules_AllowAllToAll(t *testing.T) {
	chainSuffix := "egressallowall"
	targetChainFullName := EgressChain + "_" + chainSuffix
	nft := newTestNFTablesForEgressRules(targetChainFullName)
	sourcePod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "sourcepod", Namespace: "default"}}

	policyPorts := []multiv1beta1.MultiNetworkPolicyPort{}
	resolvedDstIPs := []string{}
	resolvedDstMACs := []string{}

	renderedCount := nft.RenderEgressRules(chainSuffix, 0, resolvedDstIPs, resolvedDstMACs, policyPorts, sourcePod)
	assert.Equal(t, 1, renderedCount, "Expected 1 accept rule for allow-all egress")

	require.Len(t, nft.InternalQueue, 1, "Expected 1 operation for allow-all egress")

	addRuleOp := nft.InternalQueue[0] /* The only operation must be AddRule */
	require.Equal(t, OpAddRule, addRuleOp.Type)
	require.NotNil(t, addRuleOp.Rule)
	require.Len(t, addRuleOp.Rule.Exprs, 1, "Expected 1 expression for allow-all rule")
	verdict, ok := addRuleOp.Rule.Exprs[0].(*expr.Verdict)
	require.True(t, ok, "Expression should be a verdict")
	assert.Equal(t, expr.VerdictAccept, verdict.Kind)
}

func TestRenderEgressRules_AllowToAnyDestinationForSpecificPorts(t *testing.T) {
	chainSuffix := "egressanytofixedports"
	targetChainFullName := EgressChain + "_" + chainSuffix
	nft := newTestNFTablesForEgressRules(targetChainFullName)
	sourcePod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "sourcepod", Namespace: "default"}}

	policyPorts := []multiv1beta1.MultiNetworkPolicyPort{
		{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 9999}, Protocol: ptr.To(v1.ProtocolTCP)},
	}
	resolvedDstIPs := []string{}
	resolvedDstMACs := []string{}

	renderedCount := nft.RenderEgressRules(chainSuffix, 0, resolvedDstIPs, resolvedDstMACs, policyPorts, sourcePod)
	assert.Equal(t, 1, renderedCount, "Expected 1 accept rule")

	require.Len(t, nft.InternalQueue, 7, "Expected 7 operations")

	var addRuleOp *QueuedNftOperation
	for i := len(nft.InternalQueue) - 1; i >= 0; i-- {
		if nft.InternalQueue[i].Type == OpAddRule {
			addRuleOp = &nft.InternalQueue[i]
			break
		}
	}
	require.NotNil(t, addRuleOp, "AddRule operation not found")

	foundPortLookup := false
	foundAccept := false
	for _, exprAny := range addRuleOp.Rule.Exprs {
		if lookup, ok := exprAny.(*expr.Lookup); ok {
			if strings.HasPrefix(lookup.SetName, "mnp-tcp-port-") {
				foundPortLookup = true
			}
		}
		if verdict, ok := exprAny.(*expr.Verdict); ok && verdict.Kind == expr.VerdictAccept {
			foundAccept = true
		}
	}
	assert.True(t, foundPortLookup, "Rule should contain lookup for Port set")
	assert.True(t, foundAccept, "Rule should contain accept verdict")

	foundDstIPLookup := false
	foundDstMACLookup := false
	for _, exprAny := range addRuleOp.Rule.Exprs {
		if lookup, ok := exprAny.(*expr.Lookup); ok {
			if strings.HasPrefix(lookup.SetName, "mnp-dst-ip-") {
				foundDstIPLookup = true
			}
			if strings.HasPrefix(lookup.SetName, "mnp-dst-mac-") {
				foundDstMACLookup = true
			}
		}
	}
	assert.False(t, foundDstIPLookup, "Rule should NOT contain lookup for DstIP set when destination is any")
	assert.False(t, foundDstMACLookup, "Rule should NOT contain lookup for DstMAC set when destination is any")
}

func TestRenderEgressRules_NoValidPortsResolved(t *testing.T) {
	chainSuffix := "egressnovalidports"
	targetChainFullName := EgressChain + "_" + chainSuffix
	nft := newTestNFTablesForEgressRules(targetChainFullName)
	sourcePod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "sourcepod", Namespace: "default"},
		Spec:       v1.PodSpec{Containers: []v1.Container{{Name: "app"}}},
	}

	policyPorts := []multiv1beta1.MultiNetworkPolicyPort{
		{Port: &intstr.IntOrString{Type: intstr.String, StrVal: "nonexistent-dest-port"}, Protocol: ptr.To(v1.ProtocolTCP)},
	}
	resolvedDstIPs := []string{"203.0.113.30/32"}
	resolvedDstMACs := []string{}

	renderedCount := nft.RenderEgressRules(chainSuffix, 0, resolvedDstIPs, resolvedDstMACs, policyPorts, sourcePod)
	assert.Equal(t, 0, renderedCount, "Expected 0 accept rules as no valid ports were resolved for egress")

	assert.Len(t, nft.InternalQueue, 0, "Expected 0 operations when no valid ports are resolved for egress")
}

func isEgressCIDRRule(rule *nftables.Rule, expectedCIDR, expectedPortSetName string) bool {
	var hasCIDRMatch, hasPortLookup, hasAccept bool
	_, ipNet, err := net.ParseCIDR(expectedCIDR)
	if err != nil {
		return false
	}

	for _, exprAny := range rule.Exprs {
		if cmp, ok := exprAny.(*expr.Cmp); ok && bytes.Equal(cmp.Data, ipNet.IP.To4()) {
			/* This is a simplification; a real check would also verify the bitwise mask before it.
			 * For this test's purpose, matching the IP part of the CIDR is sufficient.
			 */
			hasCIDRMatch = true
		}
		if lookup, ok := exprAny.(*expr.Lookup); ok && lookup.SetName == expectedPortSetName {
			hasPortLookup = true
		}
		if verdict, ok := exprAny.(*expr.Verdict); ok && verdict.Kind == expr.VerdictAccept {
			hasAccept = true
		}
	}
	return hasCIDRMatch && hasPortLookup && hasAccept
}

func isEgressMACRule(rule *nftables.Rule, expectedMACSetName, expectedPortSetName string) bool {
	var hasMACLookup, hasPortLookup, hasAccept bool
	for _, exprAny := range rule.Exprs {
		if lookup, ok := exprAny.(*expr.Lookup); ok {
			if lookup.SetName == expectedMACSetName {
				hasMACLookup = true
			}
			if lookup.SetName == expectedPortSetName {
				hasPortLookup = true
			}
		}
		if verdict, ok := exprAny.(*expr.Verdict); ok && verdict.Kind == expr.VerdictAccept {
			hasAccept = true
		}
	}
	return hasMACLookup && hasPortLookup && hasAccept
}

func TestRenderEgressRules_CIDRAndMACDestination(t *testing.T) {
	chainSuffix := "egresscidrmac"
	targetChainFullName := EgressChain + "_" + chainSuffix
	nft := newTestNFTablesForEgressRules(targetChainFullName)
	sourcePod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "sourcepod", Namespace: "default"}}
	policyPorts := []multiv1beta1.MultiNetworkPolicyPort{
		{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 7000}, Protocol: ptr.To(v1.ProtocolTCP)},
	}
	resolvedDstIPs := []string{"10.200.0.0/16"}
	resolvedDstMACs := []string{"11:22:33:44:55:66"}

	renderedCount := nft.RenderEgressRules(chainSuffix, 0, resolvedDstIPs, resolvedDstMACs, policyPorts, sourcePod)
	assert.Equal(t, 2, renderedCount, "Expected 2 accept rules (1 for DstCIDR, 1 for DstMAC)")

	/* Expected ops: Flush/Add IPSet (empty), Flush/Add MACSet, Flush/Add PortSet, AddRule (CIDR), AddRule (MAC) */
	require.Len(t, nft.InternalQueue, 8, "Expected 8 operations")

	rules := findAddRuleOperationsEgress(t, nft.InternalQueue, targetChainFullName)
	require.Len(t, rules, 2, "Expected two AddRule operations")

	/* Find the names of the created sets from the queue */
	var macSetName, portSetName string
	for _, op := range nft.InternalQueue {
		if op.Type == OpAddSet && op.Set != nil {
			if strings.HasPrefix(op.Set.Name, "mnp-dst-mac-") {
				macSetName = op.Set.Name
			}
			if strings.HasPrefix(op.Set.Name, "mnp-tcp-port-") {
				portSetName = op.Set.Name
			}
		}
	}
	require.NotEmpty(t, macSetName, "MAC set name not found in queue")
	require.NotEmpty(t, portSetName, "Port set name not found in queue")

	hasCIDRRule := false
	hasMACRule := false

	for _, rule := range rules {
		if isEgressCIDRRule(rule, "10.200.0.0/16", portSetName) {
			hasCIDRRule = true
		}
		if isEgressMACRule(rule, macSetName, portSetName) {
			hasMACRule = true
		}
	}
	assert.True(t, hasCIDRRule, "Rule for DstCIDR not found or not correctly identified")
	assert.True(t, hasMACRule, "Rule for DstMAC not found or not correctly identified")
}
