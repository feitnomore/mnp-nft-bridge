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
package utils

import (
	"reflect"
	"testing"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var protocolTCP v1.Protocol = "TCP"
var protocolUDP v1.Protocol = "UDP"

var (
	port80TCP = multiv1beta1.MultiNetworkPolicyPort{
		Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 80},
		Protocol: &protocolTCP,
	}
	port53UDP = multiv1beta1.MultiNetworkPolicyPort{
		Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
		Protocol: &protocolUDP,
	}
	port22TCP = multiv1beta1.MultiNetworkPolicyPort{
		Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 22},
		Protocol: &protocolTCP,
	}
	peerIPBlock1 = multiv1beta1.MultiNetworkPolicyPeer{
		IPBlock: &multiv1beta1.IPBlock{CIDR: "192.168.1.0/24"},
	}
	peerIPBlock2 = multiv1beta1.MultiNetworkPolicyPeer{
		IPBlock: &multiv1beta1.IPBlock{CIDR: "10.0.0.0/8"},
	}
	peerPodSelector = multiv1beta1.MultiNetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "client"}},
	}
	peerNamespaceSelector = multiv1beta1.MultiNetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
	}
)

func TestGetIngress(t *testing.T) {
	ingressRule1 := multiv1beta1.MultiNetworkPolicyIngressRule{
		From:  []multiv1beta1.MultiNetworkPolicyPeer{peerIPBlock1},
		Ports: []multiv1beta1.MultiNetworkPolicyPort{port80TCP},
	}
	testCases := []struct {
		name     string
		policy   *multiv1beta1.MultiNetworkPolicy
		expected []multiv1beta1.MultiNetworkPolicyIngressRule
	}{
		{
			name: "Ingress exists",
			policy: &multiv1beta1.MultiNetworkPolicy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{ingressRule1},
				},
			},
			expected: []multiv1beta1.MultiNetworkPolicyIngressRule{ingressRule1},
		},
		{
			name:     "No Ingress",
			policy:   &multiv1beta1.MultiNetworkPolicy{},
			expected: nil,
		},
		{
			name: "Empty Ingress",
			policy: &multiv1beta1.MultiNetworkPolicy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{},
				},
			},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetIngress(tc.policy)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("Unexpected Ingress: got %+v, want %+v", actual, tc.expected)
			}
		})
	}
}

func TestGetIngressFrom(t *testing.T) {
	testCases := []struct {
		name     string
		ingress  *multiv1beta1.MultiNetworkPolicyIngressRule
		expected []multiv1beta1.MultiNetworkPolicyPeer
	}{
		{
			name: "From exists",
			ingress: &multiv1beta1.MultiNetworkPolicyIngressRule{
				From: []multiv1beta1.MultiNetworkPolicyPeer{peerIPBlock1, peerPodSelector},
			},
			expected: []multiv1beta1.MultiNetworkPolicyPeer{peerIPBlock1, peerPodSelector},
		},
		{
			name:     "No From",
			ingress:  &multiv1beta1.MultiNetworkPolicyIngressRule{},
			expected: nil,
		},
		{
			name: "Empty From",
			ingress: &multiv1beta1.MultiNetworkPolicyIngressRule{
				From: []multiv1beta1.MultiNetworkPolicyPeer{},
			},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetIngressFrom(tc.ingress)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("Unexpected From: got %+v, want %+v", actual, tc.expected)
			}
		})
	}
}

func TestGetIngressFromType(t *testing.T) {
	testCases := []struct {
		name     string
		peers    []multiv1beta1.MultiNetworkPolicyPeer
		expected string
	}{
		{
			name:     "IPBlock type first",
			peers:    []multiv1beta1.MultiNetworkPolicyPeer{peerIPBlock1, peerPodSelector},
			expected: "IPBlock",
		},
		{
			name:     "PodSelector type first",
			peers:    []multiv1beta1.MultiNetworkPolicyPeer{peerPodSelector, peerNamespaceSelector},
			expected: "PodSelector",
		},
		{
			name:     "NamespaceSelector type first",
			peers:    []multiv1beta1.MultiNetworkPolicyPeer{peerNamespaceSelector, peerIPBlock1},
			expected: "NamespaceSelector",
		},
		{
			name:     "Only IPBlock",
			peers:    []multiv1beta1.MultiNetworkPolicyPeer{peerIPBlock1},
			expected: "IPBlock",
		},
		{
			name:     "Empty peers",
			peers:    []multiv1beta1.MultiNetworkPolicyPeer{},
			expected: "",
		},
		{
			name:     "Nil peers",
			peers:    nil,
			expected: "",
		},
		{
			name:     "Peer with no specific type (should not happen with validation)",
			peers:    []multiv1beta1.MultiNetworkPolicyPeer{{}},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetIngressFromType(tc.peers)
			if actual != tc.expected {
				t.Errorf("Unexpected FromType: got '%s', want '%s'", actual, tc.expected)
			}
		})
	}
}

func TestGetIngressPorts(t *testing.T) {
	testCases := []struct {
		name     string
		ingress  *multiv1beta1.MultiNetworkPolicyIngressRule
		expected []multiv1beta1.MultiNetworkPolicyPort
	}{
		{
			name: "Ports exist",
			ingress: &multiv1beta1.MultiNetworkPolicyIngressRule{
				Ports: []multiv1beta1.MultiNetworkPolicyPort{port80TCP, port53UDP},
			},
			expected: []multiv1beta1.MultiNetworkPolicyPort{port80TCP, port53UDP},
		},
		{
			name:     "No Ports",
			ingress:  &multiv1beta1.MultiNetworkPolicyIngressRule{},
			expected: nil,
		},
		{
			name: "Empty Ports",
			ingress: &multiv1beta1.MultiNetworkPolicyIngressRule{
				Ports: []multiv1beta1.MultiNetworkPolicyPort{},
			},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetIngressPorts(tc.ingress)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("Unexpected Ports: got %+v, want %+v", actual, tc.expected)
			}
		})
	}
}

func TestGetEgress(t *testing.T) {
	egressRule1 := multiv1beta1.MultiNetworkPolicyEgressRule{
		To:    []multiv1beta1.MultiNetworkPolicyPeer{peerIPBlock2},
		Ports: []multiv1beta1.MultiNetworkPolicyPort{port22TCP},
	}
	testCases := []struct {
		name     string
		policy   *multiv1beta1.MultiNetworkPolicy
		expected []multiv1beta1.MultiNetworkPolicyEgressRule
	}{
		{
			name: "Egress exists",
			policy: &multiv1beta1.MultiNetworkPolicy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{egressRule1},
				},
			},
			expected: []multiv1beta1.MultiNetworkPolicyEgressRule{egressRule1},
		},
		{
			name:     "No Egress",
			policy:   &multiv1beta1.MultiNetworkPolicy{},
			expected: nil,
		},
		{
			name: "Empty Egress",
			policy: &multiv1beta1.MultiNetworkPolicy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{},
				},
			},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetEgress(tc.policy)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("Unexpected Egress: got %+v, want %+v", actual, tc.expected)
			}
		})
	}
}

func TestGetEgressTo(t *testing.T) {
	testCases := []struct {
		name     string
		egress   *multiv1beta1.MultiNetworkPolicyEgressRule
		expected []multiv1beta1.MultiNetworkPolicyPeer
	}{
		{
			name: "To exists",
			egress: &multiv1beta1.MultiNetworkPolicyEgressRule{
				To: []multiv1beta1.MultiNetworkPolicyPeer{peerIPBlock2, peerNamespaceSelector},
			},
			expected: []multiv1beta1.MultiNetworkPolicyPeer{peerIPBlock2, peerNamespaceSelector},
		},
		{
			name:     "No To",
			egress:   &multiv1beta1.MultiNetworkPolicyEgressRule{},
			expected: nil,
		},
		{
			name: "Empty To",
			egress: &multiv1beta1.MultiNetworkPolicyEgressRule{
				To: []multiv1beta1.MultiNetworkPolicyPeer{},
			},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetEgressTo(tc.egress)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("Unexpected To: got %+v, want %+v", actual, tc.expected)
			}
		})
	}
}

func TestGetEgressPorts(t *testing.T) {
	testCases := []struct {
		name     string
		egress   *multiv1beta1.MultiNetworkPolicyEgressRule
		expected []multiv1beta1.MultiNetworkPolicyPort
	}{
		{
			name: "Ports exist",
			egress: &multiv1beta1.MultiNetworkPolicyEgressRule{
				Ports: []multiv1beta1.MultiNetworkPolicyPort{port22TCP, port53UDP},
			},
			expected: []multiv1beta1.MultiNetworkPolicyPort{port22TCP, port53UDP},
		},
		{
			name:     "No Ports",
			egress:   &multiv1beta1.MultiNetworkPolicyEgressRule{},
			expected: nil,
		},
		{
			name: "Empty Ports",
			egress: &multiv1beta1.MultiNetworkPolicyEgressRule{
				Ports: []multiv1beta1.MultiNetworkPolicyPort{},
			},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetEgressPorts(tc.egress)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("Unexpected Ports: got %+v, want %+v", actual, tc.expected)
			}
		})
	}
}

func TestGetEgressToType(t *testing.T) {
	testCases := []struct {
		name     string
		peers    []multiv1beta1.MultiNetworkPolicyPeer
		expected string
	}{
		{
			name:     "IPBlock type first",
			peers:    []multiv1beta1.MultiNetworkPolicyPeer{peerIPBlock2, peerPodSelector},
			expected: "IPBlock",
		},
		{
			name:     "PodSelector type first",
			peers:    []multiv1beta1.MultiNetworkPolicyPeer{peerPodSelector, peerNamespaceSelector},
			expected: "PodSelector",
		},
		{
			name:     "NamespaceSelector type first",
			peers:    []multiv1beta1.MultiNetworkPolicyPeer{peerNamespaceSelector, peerIPBlock1},
			expected: "NamespaceSelector",
		},
		{
			name:     "Only NamespaceSelector",
			peers:    []multiv1beta1.MultiNetworkPolicyPeer{peerNamespaceSelector},
			expected: "NamespaceSelector",
		},
		{
			name:     "Empty peers",
			peers:    []multiv1beta1.MultiNetworkPolicyPeer{},
			expected: "",
		},
		{
			name:     "Nil peers",
			peers:    nil,
			expected: "",
		},
		{
			name:     "Peer with no specific type (should not happen with validation)",
			peers:    []multiv1beta1.MultiNetworkPolicyPeer{{}},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := GetEgressToType(tc.peers)
			if actual != tc.expected {
				t.Errorf("Unexpected ToType: got '%s', want '%s'", actual, tc.expected)
			}
		})
	}
}

func TestGetPolicyTypes(t *testing.T) {
	tests := []struct {
		name     string
		policy   *multiv1beta1.MultiNetworkPolicy
		expected []multiv1beta1.MultiPolicyType
	}{
		{
			name: "Explicit Ingress",
			policy: &multiv1beta1.MultiNetworkPolicy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
				},
			},
			expected: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		},
		{
			name: "Explicit Egress",
			policy: &multiv1beta1.MultiNetworkPolicy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress},
				},
			},
			expected: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress},
		},
		{
			name: "Explicit Ingress and Egress",
			policy: &multiv1beta1.MultiNetworkPolicy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress, multiv1beta1.PolicyTypeEgress},
				},
			},
			expected: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress, multiv1beta1.PolicyTypeEgress},
		},
		{
			name: "Inferred Ingress from rules",
			policy: &multiv1beta1.MultiNetworkPolicy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{}},
				},
			},
			expected: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		},
		{
			name: "Inferred Egress from rules",
			policy: &multiv1beta1.MultiNetworkPolicy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{{}},
				},
			},
			expected: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeEgress},
		},
		{
			name: "Inferred Ingress and Egress from rules",
			policy: &multiv1beta1.MultiNetworkPolicy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{}},
					Egress:  []multiv1beta1.MultiNetworkPolicyEgressRule{{}},
				},
			},
			expected: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress, multiv1beta1.PolicyTypeEgress},
		},
		{
			name: "Default to Ingress and Egress for isolation (podSelector set, no rules, no explicit types)",
			policy: &multiv1beta1.MultiNetworkPolicy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
				},
			},
			expected: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress, multiv1beta1.PolicyTypeEgress},
		},
		{
			name: "No types if podSelector is empty, no rules, no explicit types",
			policy: &multiv1beta1.MultiNetworkPolicy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PodSelector: metav1.LabelSelector{},
				},
			},
			expected: nil,
		},
		{
			name: "Explicit empty PolicyTypes",
			policy: &multiv1beta1.MultiNetworkPolicy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{},
				},
			},
			expected: []multiv1beta1.MultiPolicyType{},
		},
		{
			name: "PolicyTypes set, but Ingress/Egress rules also present (explicit takes precedence)",
			policy: &multiv1beta1.MultiNetworkPolicy{
				Spec: multiv1beta1.MultiNetworkPolicySpec{
					PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
					Egress:      []multiv1beta1.MultiNetworkPolicyEgressRule{{}},
				},
			},
			expected: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := GetPolicyTypes(tt.policy)
			assert.ElementsMatch(t, tt.expected, actual)
		})
	}
}

func TestHasPolicyType(t *testing.T) {
	policyWithIngress := &multiv1beta1.MultiNetworkPolicy{
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress},
		},
	}
	policyWithIngressAndEgress := &multiv1beta1.MultiNetworkPolicy{
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PolicyTypes: []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress, multiv1beta1.PolicyTypeEgress},
		},
	}
	policyInferredIngress := &multiv1beta1.MultiNetworkPolicy{
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{{}},
		},
	}
	emptyPolicy := &multiv1beta1.MultiNetworkPolicy{
		Spec: multiv1beta1.MultiNetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
		},
	}

	testCases := []struct {
		name     string
		policy   *multiv1beta1.MultiNetworkPolicy
		pType    multiv1beta1.MultiPolicyType
		expected bool
	}{
		{"Has Ingress (explicit)", policyWithIngress, multiv1beta1.PolicyTypeIngress, true},
		{"Does not have Egress (explicit)", policyWithIngress, multiv1beta1.PolicyTypeEgress, false},
		{"Has Ingress (mixed explicit)", policyWithIngressAndEgress, multiv1beta1.PolicyTypeIngress, true},
		{"Has Egress (mixed explicit)", policyWithIngressAndEgress, multiv1beta1.PolicyTypeEgress, true},
		{"Has Ingress (inferred)", policyInferredIngress, multiv1beta1.PolicyTypeIngress, true},
		{"Does not have Egress (inferred)", policyInferredIngress, multiv1beta1.PolicyTypeEgress, false},
		{"Empty policy has Ingress (default isolation)", emptyPolicy, multiv1beta1.PolicyTypeIngress, true},
		{"Empty policy has Egress (default isolation)", emptyPolicy, multiv1beta1.PolicyTypeEgress, true},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, HasPolicyType(tt.policy, tt.pType))
		})
	}
}
