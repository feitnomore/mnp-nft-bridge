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
package cache

import (
	"reflect"
	"testing"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMultiNetworkPolicyCache(t *testing.T) {
	InitializeMultiNetworkPolicyCache()

	/* Test case 1: Add MultiNetworkPolicy to cache */
	policy1 := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy1",
			Namespace: "namespace1",
		},
		Spec: multiv1beta1.MultiNetworkPolicySpec{},
	}
	AddMultiNetworkPolicy(policy1)
	expectedPolicy1 := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy1",
			Namespace: "namespace1",
		},
		Spec: multiv1beta1.MultiNetworkPolicySpec{},
	}
	if !reflect.DeepEqual(multiNetworkPolicyCache.Policies["namespace1/policy1"], expectedPolicy1) {
		t.Errorf("Policy1 not added correctly to cache")
	}

	/* Test case 2: Add another MultiNetworkPolicy to cache */
	policy2 := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy2",
			Namespace: "namespace2",
		},
		Spec: multiv1beta1.MultiNetworkPolicySpec{},
	}
	AddMultiNetworkPolicy(policy2)
	expectedPolicy2 := &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "policy2",
			Namespace: "namespace2",
		},
		Spec: multiv1beta1.MultiNetworkPolicySpec{},
	}
	if !reflect.DeepEqual(multiNetworkPolicyCache.Policies["namespace2/policy2"], expectedPolicy2) {
		t.Errorf("Policy2 not added correctly to cache")
	}

	/* Test case 3: Get all MultiNetworkPolicies from cache */
	policyList := GetMultiNetworkPolicyCache()
	if len(policyList.Items) != 2 {
		t.Errorf("Incorrect number of policies returned from cache, expected 2, got %d", len(policyList.Items))
	}

	/* Test case 4: Get namespaced MultiNetworkPolicies from cache */
	namespacedPolicyList := GetNamespacedMultiNetworkPolicyCache("namespace1")
	if len(namespacedPolicyList.Items) != 1 {
		t.Errorf("Incorrect number of policies returned from namespaced cache, expected 1, got %d", len(namespacedPolicyList.Items))
	}

	/* Test case 5: Delete MultiNetworkPolicy from cache */
	DeleteMultiNetworkPolicyFromCache("policy1", "namespace1")
	if _, ok := multiNetworkPolicyCache.Policies["namespace1/policy1"]; ok {
		t.Errorf("Policy1 not deleted from cache")
	}
	if len(multiNetworkPolicyCache.Policies) != 1 {
		t.Errorf("Incorrect number of policies in cache after deletion, expected 1, got %d", len(multiNetworkPolicyCache.Policies))
	}

	/* Test case 6: Check MultiNetworkPolicy exists in Cache */
	existsPolicy2 := MultiNetworkPolicyExistsInCache("namespace2", "policy2")
	if !existsPolicy2 {
		t.Errorf("Expected to find MultiNetworkPolicy namespace2/policy2 in cache, but it was not found")
	}

	/* Test case 7: Check MultiNetworkPolicy exists in Cache */
	existsPolicy3 := MultiNetworkPolicyExistsInCache("namespace3", "policy3")
	if existsPolicy3 {
		t.Errorf("Did not expect to find MultiNetworkPolicy namespace3/policy3 in cache, but it was found")
	}

	/* Test case 8: Get specific MultiNetworkPolicy from cache */
	fetchedPolicy := GetMultiNetworkPolicyFromCache("namespace2", "policy2")
	if !reflect.DeepEqual(fetchedPolicy, policy2) {
		t.Errorf("Incorrect Policy returned from cache")
	}
}
