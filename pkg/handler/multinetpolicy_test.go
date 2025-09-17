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
package handler

import (
	"reflect"
	"testing"

	"github.com/feitnomore/mnp-nft-bridge/pkg/cache"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

/* Helper to create a test MultiNetworkPolicy */
func testMNP(namespace, name string, labels, annotations map[string]string, spec multiv1beta1.MultiNetworkPolicySpec) *multiv1beta1.MultiNetworkPolicy {
	return &multiv1beta1.MultiNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: spec,
	}
}

var intstr80 = intstr.FromInt(80)
var intstr443 = intstr.FromInt(443)

func TestAddMultinetPolicyHandler(t *testing.T) {
	baseSpec := multiv1beta1.MultiNetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
		Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
			{Ports: []multiv1beta1.MultiNetworkPolicyPort{{Port: &intstr80}}},
		},
	}
	mnpDefaultNs := testMNP("default", "mnp1", map[string]string{"role": "test"}, nil, baseSpec)
	mnpOtherNs := testMNP("other-ns", "mnp-other", map[string]string{"role": "test-other"}, nil, baseSpec) /* MultiNetworkPolicy in another namespace */

	tests := []struct {
		name            string
		policyToAdd     *multiv1beta1.MultiNetworkPolicy
		initialCache    map[string]*multiv1beta1.MultiNetworkPolicy
		expectReconcile bool
		expectInCache   bool
	}{
		{
			name:            "Add new MNP in default namespace",
			policyToAdd:     mnpDefaultNs,
			initialCache:    map[string]*multiv1beta1.MultiNetworkPolicy{},
			expectReconcile: true,
			expectInCache:   true,
		},
		{
			name:        "Add MNP that already exists (identical) in default namespace",
			policyToAdd: mnpDefaultNs,
			initialCache: map[string]*multiv1beta1.MultiNetworkPolicy{
				"default/mnp1": mnpDefaultNs,
			},
			expectReconcile: false,
			expectInCache:   true,
		},
		{
			name:            "Add new MNP in other-ns namespace",
			policyToAdd:     mnpOtherNs,
			initialCache:    map[string]*multiv1beta1.MultiNetworkPolicy{},
			expectReconcile: true,
			expectInCache:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.InitializeMultiNetworkPolicyCache()
			for _, policy := range tt.initialCache {
				cache.AddMultiNetworkPolicy(policy)
			}

			reconcile := AddMultinetPolicy(tt.policyToAdd)
			assert.Equal(t, tt.expectReconcile, reconcile)

			if tt.expectInCache {
				cachedPolicy := cache.GetMultiNetworkPolicyFromCache(tt.policyToAdd.Namespace, tt.policyToAdd.Name)
				require.NotNil(t, cachedPolicy)
				assert.True(t, reflect.DeepEqual(tt.policyToAdd, cachedPolicy), "Cached policy does not match added policy")
			} else {
				if !tt.expectReconcile && len(tt.initialCache) > 0 && tt.initialCache[tt.policyToAdd.Namespace+"/"+tt.policyToAdd.Name] != nil {
					cachedPolicy := cache.GetMultiNetworkPolicyFromCache(tt.policyToAdd.Namespace, tt.policyToAdd.Name)
					require.NotNil(t, cachedPolicy)
				} else {
					assert.Nil(t, cache.GetMultiNetworkPolicyFromCache(tt.policyToAdd.Namespace, tt.policyToAdd.Name))
				}
			}
		})
	}
}

func TestUpdateMultinetPolicyHandler(t *testing.T) {
	baseLabels := map[string]string{"role": "frontend"}
	baseAnnots := map[string]string{"k8s.v1.cni.cncf.io/policy-for": "net1"}
	initialSpec := multiv1beta1.MultiNetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
			{Ports: []multiv1beta1.MultiNetworkPolicyPort{{Port: &intstr80}}},
		},
	}
	mnpInitialDefaultNs := testMNP("default", "mnp-update", baseLabels, baseAnnots, initialSpec)
	mnpInitialOtherNs := testMNP("other-ns", "mnp-update-other", baseLabels, baseAnnots, initialSpec)

	updatedLabels := map[string]string{"role": "frontend-v2"}
	mnpWithLabelChangeDefaultNs := testMNP("default", "mnp-update", updatedLabels, baseAnnots, initialSpec)

	updatedAnnots := map[string]string{"k8s.v1.cni.cncf.io/policy-for": "net2"}
	mnpWithAnnotChangeDefaultNs := testMNP("default", "mnp-update", baseLabels, updatedAnnots, initialSpec)

	updatedSpec := multiv1beta1.MultiNetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web-new"}},
		Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
			{Ports: []multiv1beta1.MultiNetworkPolicyPort{{Port: &intstr443}}},
		},
	}
	mnpWithSpecChangeDefaultNs := testMNP("default", "mnp-update", baseLabels, baseAnnots, updatedSpec)

	tests := []struct {
		name            string
		policyInCache   *multiv1beta1.MultiNetworkPolicy
		policyToUpdate  *multiv1beta1.MultiNetworkPolicy
		expectReconcile bool
		expectedPolicy  *multiv1beta1.MultiNetworkPolicy
	}{
		{
			name:            "Update MNP not in cache (behaves like Add) in default ns",
			policyInCache:   nil,
			policyToUpdate:  mnpInitialDefaultNs,
			expectReconcile: true,
			expectedPolicy:  mnpInitialDefaultNs,
		},
		{
			name:            "Update MNP with no changes in default ns",
			policyInCache:   mnpInitialDefaultNs.DeepCopy(),
			policyToUpdate:  mnpInitialDefaultNs.DeepCopy(),
			expectReconcile: false,
			expectedPolicy:  mnpInitialDefaultNs,
		},
		{
			name:            "Update MNP with label change in default ns",
			policyInCache:   mnpInitialDefaultNs.DeepCopy(),
			policyToUpdate:  mnpWithLabelChangeDefaultNs,
			expectReconcile: true,
			expectedPolicy:  mnpWithLabelChangeDefaultNs,
		},
		{
			name:            "Update MNP with spec change in default ns",
			policyInCache:   mnpInitialDefaultNs.DeepCopy(),
			policyToUpdate:  mnpWithSpecChangeDefaultNs,
			expectReconcile: true,
			expectedPolicy:  mnpWithSpecChangeDefaultNs,
		},
		{
			name:            "Update MNP with annotation change in default ns",
			policyInCache:   mnpInitialDefaultNs.DeepCopy(),
			policyToUpdate:  mnpWithAnnotChangeDefaultNs,
			expectReconcile: true,
			expectedPolicy:  mnpWithAnnotChangeDefaultNs,
		},
		{
			name:            "Update MNP not in cache (behaves like Add) in other-ns",
			policyInCache:   nil,
			policyToUpdate:  mnpInitialOtherNs,
			expectReconcile: true,
			expectedPolicy:  mnpInitialOtherNs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.InitializeMultiNetworkPolicyCache()
			if tt.policyInCache != nil {
				cache.AddMultiNetworkPolicy(tt.policyInCache)
			}

			reconcile := UpdateMultinetPolicy(tt.policyToUpdate)
			assert.Equal(t, tt.expectReconcile, reconcile)

			cachedPolicy := cache.GetMultiNetworkPolicyFromCache(tt.policyToUpdate.Namespace, tt.policyToUpdate.Name)

			if tt.expectReconcile || (tt.policyInCache == nil && tt.policyToUpdate != nil) {
				require.NotNil(t, cachedPolicy, "Policy deveria estar no cache")
				assert.True(t, reflect.DeepEqual(tt.expectedPolicy, cachedPolicy), "Cached policy spec/labels do not correspond to expectations")
			} else if tt.policyInCache != nil {
				require.NotNil(t, cachedPolicy, "Policy deveria ainda estar no cache")
				assert.True(t, reflect.DeepEqual(tt.policyInCache, cachedPolicy), "Cached policy spec/labels they shouldn't have changed")
			}
		})
	}
}

func TestDeleteMultinetPolicyHandler(t *testing.T) {
	mnpToDeleteDefaultNs := testMNP("default", "mnp-del", nil, nil, multiv1beta1.MultiNetworkPolicySpec{})
	mnpToDeleteOtherNs := testMNP("other-ns", "mnp-del-other", nil, nil, multiv1beta1.MultiNetworkPolicySpec{}) /* MultiNetworkPolicy in other namespace */

	tests := []struct {
		name             string
		policyToDelete   *multiv1beta1.MultiNetworkPolicy
		initialCache     map[string]*multiv1beta1.MultiNetworkPolicy
		expectReconcile  bool
		expectNotInCache bool
	}{
		{
			name:           "Delete existing MNP in default namespace",
			policyToDelete: mnpToDeleteDefaultNs,
			initialCache: map[string]*multiv1beta1.MultiNetworkPolicy{
				"default/mnp-del": mnpToDeleteDefaultNs,
			},
			expectReconcile:  true,
			expectNotInCache: true,
		},
		{
			name:             "Delete MNP not in cache",
			policyToDelete:   mnpToDeleteDefaultNs, /* Using the same object, but the cache will be empty */
			initialCache:     map[string]*multiv1beta1.MultiNetworkPolicy{},
			expectReconcile:  true,
			expectNotInCache: true,
		},
		{
			name:           "Delete existing MNP in other-ns namespace",
			policyToDelete: mnpToDeleteOtherNs,
			initialCache: map[string]*multiv1beta1.MultiNetworkPolicy{
				"other-ns/mnp-del-other": mnpToDeleteOtherNs,
			},
			expectReconcile:  true,
			expectNotInCache: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.InitializeMultiNetworkPolicyCache()
			for _, policy := range tt.initialCache {
				cache.AddMultiNetworkPolicy(policy)
			}

			reconcile := DeleteMultinetPolicy(tt.policyToDelete)
			assert.Equal(t, tt.expectReconcile, reconcile)

			if tt.expectNotInCache {
				assert.False(t, cache.MultiNetworkPolicyExistsInCache(tt.policyToDelete.Namespace, tt.policyToDelete.Name))
			}
		})
	}
}
