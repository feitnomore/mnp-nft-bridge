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
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/* Helper for creating a test NetworkAttachmentDefinition */
func testNAD(namespace, name string, labels map[string]string, config string) *netdefv1.NetworkAttachmentDefinition {
	return &netdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: netdefv1.NetworkAttachmentDefinitionSpec{
			Config: config,
		},
	}
}

func TestAddNetAttachHandler(t *testing.T) {
	nad1 := testNAD("default", "nad1", map[string]string{"type": "bridge"}, `{"cniVersion":"0.3.1","name":"br-net","type":"bridge"}`)

	tests := []struct {
		name            string
		nadToAdd        *netdefv1.NetworkAttachmentDefinition
		initialCache    map[string]*netdefv1.NetworkAttachmentDefinition
		expectReconcile bool
		expectInCache   bool
	}{
		{
			name:            "Add new NAD",
			nadToAdd:        nad1,
			initialCache:    map[string]*netdefv1.NetworkAttachmentDefinition{},
			expectReconcile: true,
			expectInCache:   true,
		},
		{
			name:     "Add NAD that already exists (identical)",
			nadToAdd: nad1,
			initialCache: map[string]*netdefv1.NetworkAttachmentDefinition{
				"default/nad1": nad1,
			},
			expectReconcile: false,
			expectInCache:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.InitializeNetworkAttachmentDefinitionCache()
			for _, nad := range tt.initialCache {
				cache.AddNetworkAttachmentDefinitionCache(nad)
			}

			reconcile := AddNetAttach(tt.nadToAdd)
			assert.Equal(t, tt.expectReconcile, reconcile)

			if tt.expectInCache {
				cachedNAD := cache.GetNetworkAttachmentDefinitionFromCache(tt.nadToAdd.Namespace, tt.nadToAdd.Name)
				require.NotNil(t, cachedNAD)
				assert.True(t, reflect.DeepEqual(tt.nadToAdd.Spec, cachedNAD.Spec), "Cached NAD Spec does not match")
				assert.True(t, reflect.DeepEqual(tt.nadToAdd.Labels, cachedNAD.Labels), "Cached NAD Labels do not match")
			} else {
				if !tt.expectReconcile && len(tt.initialCache) > 0 && tt.initialCache[tt.nadToAdd.Namespace+"/"+tt.nadToAdd.Name] != nil {
					cachedNAD := cache.GetNetworkAttachmentDefinitionFromCache(tt.nadToAdd.Namespace, tt.nadToAdd.Name)
					require.NotNil(t, cachedNAD)
				} else {
					assert.Nil(t, cache.GetNetworkAttachmentDefinitionFromCache(tt.nadToAdd.Namespace, tt.nadToAdd.Name))
				}
			}
		})
	}
}

func TestUpdateNetAttachHandler(t *testing.T) {
	baseLabels := map[string]string{"cni": "multus"}
	initialConfig := `{"cniVersion":"0.3.1","name":"net-a","type":"bridge"}`
	nadInitial := testNAD("kube-system", "nad-update", baseLabels, initialConfig)

	updatedLabels := map[string]string{"cni": "multus", "updated": "true"}
	nadWithLabelChange := testNAD("kube-system", "nad-update", updatedLabels, initialConfig)

	updatedConfig := `{"cniVersion":"0.4.0","name":"net-a-new","type":"bridge","bridge":"br1"}`
	nadWithSpecChange := testNAD("kube-system", "nad-update", baseLabels, updatedConfig)

	tests := []struct {
		name                string
		nadInCache          *netdefv1.NetworkAttachmentDefinition
		nadToUpdate         *netdefv1.NetworkAttachmentDefinition
		expectReconcile     bool
		expectedCachedState *netdefv1.NetworkAttachmentDefinition
	}{
		{
			name:                "Update NAD not in cache (behaves like Add)",
			nadInCache:          nil,
			nadToUpdate:         nadInitial,
			expectReconcile:     true,
			expectedCachedState: nadInitial, // Expect it to be added
		},
		{
			name:                "Update NAD with no changes",
			nadInCache:          nadInitial.DeepCopy(),
			nadToUpdate:         nadInitial.DeepCopy(),
			expectReconcile:     false,
			expectedCachedState: nadInitial, // Remains the same
		},
		{
			name:                "Update NAD with label change",
			nadInCache:          nadInitial.DeepCopy(),
			nadToUpdate:         nadWithLabelChange,
			expectReconcile:     true,
			expectedCachedState: nadWithLabelChange,
		},
		{
			name:                "Update NAD with spec (config) change",
			nadInCache:          nadInitial.DeepCopy(),
			nadToUpdate:         nadWithSpecChange,
			expectReconcile:     true,
			expectedCachedState: nadWithSpecChange,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.InitializeNetworkAttachmentDefinitionCache()
			if tt.nadInCache != nil {
				cache.AddNetworkAttachmentDefinitionCache(tt.nadInCache)
			}

			reconcile := UpdateNetAttach(tt.nadToUpdate)
			assert.Equal(t, tt.expectReconcile, reconcile)

			cachedNAD := cache.GetNetworkAttachmentDefinitionFromCache(tt.nadToUpdate.Namespace, tt.nadToUpdate.Name)

			switch {
			case tt.nadInCache == nil && tt.expectReconcile: /* Case: "Add" via Update */
				require.NotNil(t, cachedNAD, "NAD should be in cache (added via Update)")
				assert.True(t, reflect.DeepEqual(tt.expectedCachedState.Spec, cachedNAD.Spec), "Cached NAD Spec does not match expected after add via update")
				assert.True(t, reflect.DeepEqual(tt.expectedCachedState.Labels, cachedNAD.Labels), "Cached NAD Labels do not match expected after add via update")
			case tt.nadInCache != nil: /* Case: update of an existing item */
				require.NotNil(t, cachedNAD, "NAD should still be in cache")
				assert.True(t, reflect.DeepEqual(tt.expectedCachedState.Spec, cachedNAD.Spec), "Cached NAD Spec does not match expected state after update")
				assert.True(t, reflect.DeepEqual(tt.expectedCachedState.Labels, cachedNAD.Labels), "Cached NAD Labels do not match expected state after update")
			default: /* nadInCache is nil and we don't expect reconcile (should not happen with current cases) */
				assert.Nil(t, cachedNAD, "NAD should not be in cache")
			}
		})
	}
}

func TestDeleteNetAttachHandler(t *testing.T) {
	nadToDelete := testNAD("default", "nad-del", nil, "")

	tests := []struct {
		name            string
		nadToDelete     *netdefv1.NetworkAttachmentDefinition
		initialCache    map[string]*netdefv1.NetworkAttachmentDefinition
		expectReconcile bool
		expectInCache   bool
	}{
		{
			name:        "Delete existing NAD",
			nadToDelete: nadToDelete,
			initialCache: map[string]*netdefv1.NetworkAttachmentDefinition{
				"default/nad-del": nadToDelete,
			},
			expectReconcile: true,
			expectInCache:   false,
		},
		{
			name:            "Delete NAD not in cache",
			nadToDelete:     nadToDelete,
			initialCache:    map[string]*netdefv1.NetworkAttachmentDefinition{},
			expectReconcile: true,
			expectInCache:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.InitializeNetworkAttachmentDefinitionCache()
			for _, nad := range tt.initialCache {
				cache.AddNetworkAttachmentDefinitionCache(nad)
			}

			reconcile := DeleteNetAttach(tt.nadToDelete)
			assert.Equal(t, tt.expectReconcile, reconcile)

			if tt.expectInCache {
				assert.True(t, cache.NetworkAttachmentDefinitionExistsInCache(tt.nadToDelete.Namespace, tt.nadToDelete.Name))
			} else {
				assert.False(t, cache.NetworkAttachmentDefinitionExistsInCache(tt.nadToDelete.Namespace, tt.nadToDelete.Name))
			}
		})
	}
}
