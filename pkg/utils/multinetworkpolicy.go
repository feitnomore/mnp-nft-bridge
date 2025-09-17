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
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"k8s.io/klog/v2"
)

func GetIngress(policy *multiv1beta1.MultiNetworkPolicy) []multiv1beta1.MultiNetworkPolicyIngressRule {
	klog.V(8).Infof("GetIngress...")
	if len(policy.Spec.Ingress) > 0 {
		klog.V(8).Infof("Ingress Length > 0")
		return policy.Spec.Ingress
	}
	return nil
}

func GetIngressFrom(ingress *multiv1beta1.MultiNetworkPolicyIngressRule) []multiv1beta1.MultiNetworkPolicyPeer {
	if len(ingress.From) > 0 {
		return ingress.From
	}
	return nil
}

func GetIngressFromType(ingress []multiv1beta1.MultiNetworkPolicyPeer) string {
	for i := range ingress {
		klog.V(8).Infof("range %d", i)
		switch {
		case ingress[i].IPBlock != nil:
			return "IPBlock"
		case ingress[i].NamespaceSelector != nil:
			return "NamespaceSelector"
		case ingress[i].PodSelector != nil:
			return "PodSelector"
		}
	}
	return ""
}

func GetIngressPorts(ingress *multiv1beta1.MultiNetworkPolicyIngressRule) []multiv1beta1.MultiNetworkPolicyPort {
	if len(ingress.Ports) > 0 {
		return ingress.Ports
	}
	return nil
}

func GetEgress(policy *multiv1beta1.MultiNetworkPolicy) []multiv1beta1.MultiNetworkPolicyEgressRule {
	klog.V(8).Infof("GetEgress...")
	if len(policy.Spec.Egress) > 0 {
		klog.V(8).Infof("Egress Length > 0")
		return policy.Spec.Egress
	}
	return nil
}

func GetEgressTo(egress *multiv1beta1.MultiNetworkPolicyEgressRule) []multiv1beta1.MultiNetworkPolicyPeer {
	if len(egress.To) > 0 {
		return egress.To
	}
	return nil
}

func GetEgressPorts(egress *multiv1beta1.MultiNetworkPolicyEgressRule) []multiv1beta1.MultiNetworkPolicyPort {
	if len(egress.Ports) > 0 {
		return egress.Ports
	}
	return nil
}

func GetEgressToType(egress []multiv1beta1.MultiNetworkPolicyPeer) string {
	for i := range egress {
		klog.V(8).Infof("range %d", i)
		switch {
		case egress[i].IPBlock != nil:
			return "IPBlock"
		case egress[i].NamespaceSelector != nil:
			return "NamespaceSelector"
		case egress[i].PodSelector != nil:
			return "PodSelector"
		}
	}
	return ""
}

func GetPolicyTypes(policy *multiv1beta1.MultiNetworkPolicy) []multiv1beta1.MultiPolicyType {
	// if len(policy.Spec.PolicyTypes) > 0 {
	// The CRD spec indicates that if PolicyTypes is present, it MUST be respected.
	// An empty `policyTypes: []` field means the policy applies to NO direction.
	// If the field is omitted entirely (nil slice), we infer from rules.
	if policy.Spec.PolicyTypes != nil {
		klog.V(7).Infof("Policy %s/%s: Explicit PolicyTypes: %v", policy.Namespace, policy.Name, policy.Spec.PolicyTypes)
		return policy.Spec.PolicyTypes
	}

	var inferredTypes []multiv1beta1.MultiPolicyType
	hasIngressRules := len(policy.Spec.Ingress) > 0
	hasEgressRules := len(policy.Spec.Egress) > 0

	if hasIngressRules {
		inferredTypes = append(inferredTypes, multiv1beta1.PolicyTypeIngress)
	}
	if hasEgressRules {
		inferredTypes = append(inferredTypes, multiv1beta1.PolicyTypeEgress)
	}

	if !hasIngressRules && !hasEgressRules && policy.Spec.PodSelector.Size() > 0 {
		klog.V(6).Infof("Policy %s/%s: No explicit rules and podSelector is set. Defaulting PolicyTypes to Ingress & Egress for isolation.", policy.Namespace, policy.Name)
		return []multiv1beta1.MultiPolicyType{multiv1beta1.PolicyTypeIngress, multiv1beta1.PolicyTypeEgress}
	}

	if len(inferredTypes) > 0 {
		klog.V(7).Infof("Policy %s/%s: Inferred PolicyTypes: %v", policy.Namespace, policy.Name, inferredTypes)
		return inferredTypes
	}

	klog.V(7).Infof("Policy %s/%s: No explicit PolicyTypes, no rules, or no podSelector. Returning empty PolicyTypes.", policy.Namespace, policy.Name)
	return nil
}

func HasPolicyType(policy *multiv1beta1.MultiNetworkPolicy, pType multiv1beta1.MultiPolicyType) bool {
	types := GetPolicyTypes(policy)
	for _, t := range types {
		if t == pType {
			return true
		}
	}
	return false
}
