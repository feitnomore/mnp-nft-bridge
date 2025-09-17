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

func newTestNFTablesForIngressRules(targetChainFullName string) *NFTables {
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

/* Helper to find OpAddRule operations in the queue and check their expressionss */
func findAddRuleOperations(t *testing.T, queue []QueuedNftOperation, targetChainName string) []*nftables.Rule {
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

func TestRenderIngressRules_BasicIPBlockAndPort(t *testing.T) {
	chainSuffix := "testbasic"
	targetChainFullName := IngressChain + "_" + chainSuffix
	nft := newTestNFTablesForIngressRules(targetChainFullName)

	targetPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "targetpod", Namespace: "default"},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{Ports: []v1.ContainerPort{{Name: "http", ContainerPort: 80, Protocol: v1.ProtocolTCP}}},
			},
		},
	}
	policyPorts := []multiv1beta1.MultiNetworkPolicyPort{
		{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 80}, Protocol: ptr.To(v1.ProtocolTCP)},
	}
	resolvedIPs := []string{"192.168.1.10/32"}
	resolvedMACs := []string{}

	/* For this test, the original 'from' rule would contain the ipBlock. */
	originalFromRule := []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.10/32"}}}
	renderedCount := nft.RenderIngressRules(chainSuffix, 0, resolvedIPs, resolvedMACs, policyPorts, originalFromRule, targetPod)
	assert.Equal(t, 1, renderedCount, "Expected 1 accept rule to be rendered")

	/* Operations Expected */
	require.Len(t, nft.InternalQueue, 7, "Expected 7 operations in queue")

	/* Check IP Set (indexes 0 and 1) */
	ipFlushOp := nft.InternalQueue[0]
	require.Equal(t, OpFlushSet, ipFlushOp.Type)
	assert.True(t, strings.HasPrefix(ipFlushOp.Set.Name, "mnp-src-ip-"), "IP FlushSet name prefix mismatch")

	ipSetOp := nft.InternalQueue[1]
	require.Equal(t, OpAddSet, ipSetOp.Type)
	require.NotNil(t, ipSetOp.Set)
	assert.True(t, strings.HasPrefix(ipSetOp.Set.Name, "mnp-src-ip-"), "IP AddSet name prefix mismatch")
	assert.Equal(t, nftables.TypeIPAddr, ipSetOp.Set.KeyType)
	require.Len(t, ipSetOp.SetElements, 1)
	assert.True(t, bytes.Equal(net.ParseIP("192.168.1.10").To4(), ipSetOp.SetElements[0].Key), "IP element mismatch")

	/* Check MAC Set (indexes 2 and 3) - must be created empty */
	macFlushOp := nft.InternalQueue[2]
	require.Equal(t, OpFlushSet, macFlushOp.Type)
	assert.True(t, strings.HasPrefix(macFlushOp.Set.Name, "mnp-src-mac-"), "MAC FlushSet name prefix mismatch")

	macSetOp := nft.InternalQueue[3]
	require.Equal(t, OpAddSet, macSetOp.Type)
	require.NotNil(t, macSetOp.Set)
	assert.True(t, strings.HasPrefix(macSetOp.Set.Name, "mnp-src-mac-"), "MAC AddSet name prefix mismatch")
	assert.Equal(t, nftables.TypeEtherAddr, macSetOp.Set.KeyType)
	assert.Empty(t, macSetOp.SetElements, "MAC set should be empty")

	/* Check Port Set (indexes 4 and 5) */
	portFlushOp := nft.InternalQueue[4]
	require.Equal(t, OpFlushSet, portFlushOp.Type)
	assert.True(t, strings.HasPrefix(portFlushOp.Set.Name, "mnp-tcp-port-"), "TCP Port FlushSet name prefix mismatch")

	portSetOp := nft.InternalQueue[5]
	require.Equal(t, OpAddSet, portSetOp.Type)
	require.NotNil(t, portSetOp.Set)
	assert.True(t, strings.HasPrefix(portSetOp.Set.Name, "mnp-tcp-port-"), "TCP Port AddSet name prefix mismatch")
	assert.Equal(t, nftables.TypeInetService, portSetOp.Set.KeyType)
	require.Len(t, portSetOp.SetElements, 1)
	assert.Equal(t, binaryutil.BigEndian.PutUint16(80), portSetOp.SetElements[0].Key)

	/* Check Accept Rule (index 6) */
	addRuleOp := nft.InternalQueue[6]
	require.Equal(t, OpAddRule, addRuleOp.Type)
	require.NotNil(t, addRuleOp.Rule)
	assert.Equal(t, targetChainFullName, addRuleOp.Rule.Chain.Name)

	foundIPLookup := false
	foundPortLookup := false
	foundAccept := false
	for _, exprAny := range addRuleOp.Rule.Exprs {
		if lookup, ok := exprAny.(*expr.Lookup); ok {
			if strings.HasPrefix(lookup.SetName, "mnp-src-ip-") {
				foundIPLookup = true
			}
			if strings.HasPrefix(lookup.SetName, "mnp-tcp-port-") {
				foundPortLookup = true
			}
		}
		if verdict, ok := exprAny.(*expr.Verdict); ok && verdict.Kind == expr.VerdictAccept {
			foundAccept = true
		}
	}
	assert.True(t, foundIPLookup, "Rule should contain lookup for IP set")
	assert.True(t, foundPortLookup, "Rule should contain lookup for Port set")
	assert.True(t, foundAccept, "Rule should contain accept verdict")
}

func TestRenderIngressRules_NamedPortResolution(t *testing.T) {
	chainSuffix := "namedport"
	targetChainFullName := IngressChain + "_" + chainSuffix
	nft := newTestNFTablesForIngressRules(targetChainFullName)

	targetPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "targetpod", Namespace: "default"},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name: "app",
					Ports: []v1.ContainerPort{
						{Name: "web", ContainerPort: 8080, Protocol: v1.ProtocolTCP},
						{Name: "metrics", ContainerPort: 9090, Protocol: v1.ProtocolTCP},
						{Name: "dns-udp", ContainerPort: 1053, Protocol: v1.ProtocolUDP},
					},
				},
			},
		},
	}
	policyPorts := []multiv1beta1.MultiNetworkPolicyPort{
		{Port: &intstr.IntOrString{Type: intstr.String, StrVal: "web"}, Protocol: ptr.To(v1.ProtocolTCP)},
		{Port: &intstr.IntOrString{Type: intstr.String, StrVal: "metrics"}, Protocol: ptr.To(v1.ProtocolTCP)},
		{Port: &intstr.IntOrString{Type: intstr.String, StrVal: "dns-udp"}, Protocol: ptr.To(v1.ProtocolUDP)},
		{Port: &intstr.IntOrString{Type: intstr.String, StrVal: "nonexistent"}, Protocol: ptr.To(v1.ProtocolTCP)},
	}
	resolvedIPs := []string{"10.0.0.1/32"}
	resolvedMACs := []string{}

	/* The original 'from' rule would contain the ipBlock. */
	originalFromRule := []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "10.0.0.1/32"}}}
	renderedCount := nft.RenderIngressRules(chainSuffix, 0, resolvedIPs, resolvedMACs, policyPorts, originalFromRule, targetPod)
	assert.Equal(t, 2, renderedCount, "Expected 2 accept rules (1 for TCP set, 1 for UDP set)")

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
	require.Len(t, tcpPortElements, 2, "Expected 2 TCP ports in the set")
	expectedTCPElements := []nftables.SetElement{
		{Key: binaryutil.BigEndian.PutUint16(8080)},
		{Key: binaryutil.BigEndian.PutUint16(9090)},
	}
	assert.ElementsMatch(t, expectedTCPElements, tcpPortElements)

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
	assert.Equal(t, binaryutil.BigEndian.PutUint16(1053), udpPortElements[0].Key)
}

func TestRenderIngressRules_AllowAllFromAll(t *testing.T) {
	chainSuffix := "allowall"
	targetChainFullName := IngressChain + "_" + chainSuffix
	nft := newTestNFTablesForIngressRules(targetChainFullName)
	targetPod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "targetpod", Namespace: "default"}}

	policyPorts := []multiv1beta1.MultiNetworkPolicyPort{}
	resolvedIPs := []string{}
	resolvedMACs := []string{}

	/* For this case, the original 'from' rule would be empty. */
	originalFromRule := []multiv1beta1.MultiNetworkPolicyPeer{}
	renderedCount := nft.RenderIngressRules(chainSuffix, 0, resolvedIPs, resolvedMACs, policyPorts, originalFromRule, targetPod)
	assert.Equal(t, 1, renderedCount, "Expected 1 accept rule for allow-all")
	require.Len(t, nft.InternalQueue, 1, "Expected 1 operation for allow-all")

	addRuleOp := nft.InternalQueue[0] /* The only operation should be AddRule */
	require.Equal(t, OpAddRule, addRuleOp.Type)
	require.NotNil(t, addRuleOp.Rule)
	require.Len(t, addRuleOp.Rule.Exprs, 1, "Expected 1 expression for allow-all rule")
	verdict, ok := addRuleOp.Rule.Exprs[0].(*expr.Verdict)
	require.True(t, ok, "Expression should be a verdict")
	assert.Equal(t, expr.VerdictAccept, verdict.Kind)
}

func TestRenderIngressRules_AllowFromAnySourceToSpecificPorts(t *testing.T) {
	chainSuffix := "anytofixedports"
	targetChainFullName := IngressChain + "_" + chainSuffix
	nft := newTestNFTablesForIngressRules(targetChainFullName)
	targetPod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "targetpod", Namespace: "default"}}

	policyPorts := []multiv1beta1.MultiNetworkPolicyPort{
		{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 80}, Protocol: ptr.To(v1.ProtocolTCP)},
	}
	resolvedIPs := []string{}
	resolvedMACs := []string{}

	/* For this case, the original 'from' rule would be empty. */
	originalFromRule := []multiv1beta1.MultiNetworkPolicyPeer{}
	renderedCount := nft.RenderIngressRules(chainSuffix, 0, resolvedIPs, resolvedMACs, policyPorts, originalFromRule, targetPod)
	assert.Equal(t, 1, renderedCount, "Expected 1 accept rule")

	/* Expected 7 Operations: */
	require.Len(t, nft.InternalQueue, 7, "Expected 7 operations")

	var addRuleOp *QueuedNftOperation
	/* The AddRule rule will be the last one after the sets */
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

	foundIPLookup := false
	foundMACLookup := false
	for _, exprAny := range addRuleOp.Rule.Exprs {
		if lookup, ok := exprAny.(*expr.Lookup); ok {
			if strings.HasPrefix(lookup.SetName, "mnp-src-ip-") {
				foundIPLookup = true
			}
			if strings.HasPrefix(lookup.SetName, "mnp-src-mac-") {
				foundMACLookup = true
			}
		}
	}
	assert.False(t, foundIPLookup, "Rule should NOT contain lookup for IP set when source is any")
	assert.False(t, foundMACLookup, "Rule should NOT contain lookup for MAC set when source is any")
}

func TestRenderIngressRules_NoValidPortsResolved(t *testing.T) {
	chainSuffix := "novalidports"
	targetChainFullName := IngressChain + "_" + chainSuffix
	nft := newTestNFTablesForIngressRules(targetChainFullName)
	targetPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "targetpod", Namespace: "default"},
		Spec:       v1.PodSpec{Containers: []v1.Container{{Name: "app"}}},
	}

	policyPorts := []multiv1beta1.MultiNetworkPolicyPort{
		{Port: &intstr.IntOrString{Type: intstr.String, StrVal: "nonexistent-port"}, Protocol: ptr.To(v1.ProtocolTCP)},
	}
	resolvedIPs := []string{"10.0.0.1/32"}
	resolvedMACs := []string{}

	/* The original 'from' rule would contain the ipBlock. */
	originalFromRule := []multiv1beta1.MultiNetworkPolicyPeer{{IPBlock: &multiv1beta1.IPBlock{CIDR: "10.0.0.1/32"}}}
	renderedCount := nft.RenderIngressRules(chainSuffix, 0, resolvedIPs, resolvedMACs, policyPorts, originalFromRule, targetPod)
	assert.Equal(t, 0, renderedCount, "Expected 0 accept rules as no valid ports were resolved")

	assert.Len(t, nft.InternalQueue, 0, "Expected 0 operations when no valid ports are resolved")
}

func isIngressCIDRRule(rule *nftables.Rule, expectedCIDR, expectedPortSetName string) bool {
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

func isIngressMACRule(rule *nftables.Rule, expectedMACSetName, expectedPortSetName string) bool {
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

func TestRenderIngressRules_CIDRAndMACSource(t *testing.T) {
	chainSuffix := "cidrmac"
	targetChainFullName := IngressChain + "_" + chainSuffix
	nft := newTestNFTablesForIngressRules(targetChainFullName)
	targetPod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "targetpod", Namespace: "default"}}
	policyPorts := []multiv1beta1.MultiNetworkPolicyPort{
		{Port: &intstr.IntOrString{Type: intstr.Int, IntVal: 5000}, Protocol: ptr.To(v1.ProtocolTCP)},
	}
	resolvedIPs := []string{"172.16.0.0/24"}
	resolvedMACs := []string{"00:AA:BB:CC:DD:EE"}

	/* The original 'from' rule would contain both. */
	originalFromRule := []multiv1beta1.MultiNetworkPolicyPeer{
		{IPBlock: &multiv1beta1.IPBlock{CIDR: "172.16.0.0/24"}},
		/* MAC resolution comes from pod/ns selectors, so let's simulate that. */
	}
	renderedCount := nft.RenderIngressRules(chainSuffix, 0, resolvedIPs, resolvedMACs, policyPorts, originalFromRule, targetPod)
	assert.Equal(t, 2, renderedCount, "Expected 2 accept rules")

	/* Expected ops: Flush/Add IPSet (empty), Flush/Add MACSet, Flush/Add PortSet, AddRule (CIDR), AddRule (MAC) */
	require.Len(t, nft.InternalQueue, 8, "Expected 8 operations")

	rules := findAddRuleOperations(t, nft.InternalQueue, targetChainFullName)
	require.Len(t, rules, 2, "Expected two AddRule operations")

	/* Find the names of the created sets from the queue */
	var macSetName, portSetName string
	for _, op := range nft.InternalQueue {
		if op.Type == OpAddSet && op.Set != nil {
			if strings.HasPrefix(op.Set.Name, "mnp-src-mac-") {
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

		if isIngressCIDRRule(rule, "172.16.0.0/24", portSetName) {
			hasCIDRRule = true
		}
		if isIngressMACRule(rule, macSetName, portSetName) {
			hasMACRule = true
		}
	}
	assert.True(t, hasCIDRRule, "Rule for CIDR source not found or not correctly identified")
	assert.True(t, hasMACRule, "Rule for MAC source not found or not correctly identified")
}
