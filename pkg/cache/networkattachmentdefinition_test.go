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

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNetworkAttachmentDefinitionCache(t *testing.T) {
	InitializeNetworkAttachmentDefinitionCache()
	/* Clear the cache at the end of the test so as not to affect other tests in the same package */
	defer InitializeNetworkAttachmentDefinitionCache()

	/* Test case 1: Add NetworkAttachmentDefinition to cache */
	definition1 := &netdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "definition1",
			Namespace: "namespace1",
		},
		Spec: netdefv1.NetworkAttachmentDefinitionSpec{Config: `{"type": "bridge-type-from-config"}`},
	}
	AddNetworkAttachmentDefinitionCache(definition1)
	expectedDefinition1 := &netdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "definition1",
			Namespace: "namespace1",
		},
		Spec: netdefv1.NetworkAttachmentDefinitionSpec{Config: `{"type": "bridge-type-from-config"}`},
	}
	if !reflect.DeepEqual(networkAttachmentDefinitionCache.Definitions["namespace1/definition1"], expectedDefinition1) {
		t.Errorf("Definition1 not added correctly to cache")
	}

	/* Test case 2: Add another NetworkAttachmentDefinition to cache */
	definition2 := &netdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "definition2",
			Namespace: "namespace2",
		},
		Spec: netdefv1.NetworkAttachmentDefinitionSpec{},
	}
	AddNetworkAttachmentDefinitionCache(definition2)
	expectedDefinition2 := &netdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "definition2",
			Namespace: "namespace2",
		},
		Spec: netdefv1.NetworkAttachmentDefinitionSpec{},
	}
	if !reflect.DeepEqual(networkAttachmentDefinitionCache.Definitions["namespace2/definition2"], expectedDefinition2) {
		t.Errorf("Definition2 not added correctly to cache")
	}

	/* Test case 3: Get all NetworkAttachmentDefinitions from cache */
	networkList := GetNetworkAttachmentDefinitionCache()
	if len(networkList.Items) != 2 {
		t.Errorf("Incorrect number of definitions returned from cache, expected 2, got %d", len(networkList.Items))
	}

	/* Test case 4: Get namespaced NetworkAttachmentDefinitions from cache */
	namespacedNetworkList := GetNamespacedNetworkAttachmentDefinitionCache("namespace1")
	if len(namespacedNetworkList.Items) != 1 {
		t.Errorf("Incorrect number of definitions returned from namespaced cache, expected 1, got %d", len(namespacedNetworkList.Items))
	}

	/* Test case 5: Check Definition exists in Cache */
	existsDef2 := NetworkAttachmentDefinitionExistsInCache("namespace2", "definition2")
	if !existsDef2 {
		t.Errorf("Expected to find NetworkAttachmentDefinition namespace2/definition2 in cache, but it was not found")
	}

	/* Test case 6: Check Definition exists in Cache */
	existsDef3 := NetworkAttachmentDefinitionExistsInCache("namespace3", "definition3")
	if existsDef3 {
		t.Errorf("Did not expect to find NetworkAttachmentDefinition namespace3/definition3 in cache, but it was found")
	}

	/* Test case 7: Get specific Definition from cache */
	fetchedNetworkAttachmentDefinition := GetNetworkAttachmentDefinitionFromCache("namespace1", "definition1")
	if !reflect.DeepEqual(fetchedNetworkAttachmentDefinition, expectedDefinition1) {
		t.Errorf("Incorrect Network Attachment Definition returned from cache")
	}

	/* Test case 8: Delete NetworkAttachmentDefinition from cache */
	originalCacheState := make(map[string]*netdefv1.NetworkAttachmentDefinition)
	for k, v := range networkAttachmentDefinitionCache.Definitions {
		originalCacheState[k] = v
	}
	InitializeNetworkAttachmentDefinitionCache() // Limpa o cache para este sub-teste

	defInCacheBeforeDelete := &netdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "temp-def-1", Namespace: "temp-ns"},
	}
	defToBeDeleted := &netdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "def-to-delete", Namespace: "ns-delete"},
	}
	AddNetworkAttachmentDefinitionCache(defInCacheBeforeDelete)
	AddNetworkAttachmentDefinitionCache(defToBeDeleted)

	require.True(t, NetworkAttachmentDefinitionExistsInCache("ns-delete", "def-to-delete"), "Definition 'def-to-delete' should exist before delete")
	require.True(t, NetworkAttachmentDefinitionExistsInCache("temp-ns", "temp-def-1"), "Definition 'temp-def-1' should exist before delete")
	assert.Len(t, networkAttachmentDefinitionCache.Definitions, 2, "Cache should have 2 items before delete for isolated delete test")

	DeleteNetworkAttachmentDefinitionFromCache("ns-delete", "def-to-delete")

	assert.False(t, NetworkAttachmentDefinitionExistsInCache("ns-delete", "def-to-delete"), "Definition 'def-to-delete' should not exist after delete")
	assert.Nil(t, GetNetworkAttachmentDefinitionFromCache("ns-delete", "def-to-delete"), "Get 'def-to-delete' after delete should return nil")

	assert.True(t, NetworkAttachmentDefinitionExistsInCache("temp-ns", "temp-def-1"), "Definition 'temp-def-1' should still exist after deleting another")
	assert.Len(t, networkAttachmentDefinitionCache.Definitions, 1, "Cache size should be 1 after deleting one item in isolated delete test")

	/* Restore the original cache state */
	networkAttachmentDefinitionCache.Definitions = originalCacheState

	if !NetworkAttachmentDefinitionExistsInCache("namespace1", "definition1") {
		AddNetworkAttachmentDefinitionCache(definition1)
	}
	driver := GetNetworkAttachmentDefinitionDriver("namespace1", "definition1")
	assert.Equal(t, "bridge-type-from-config", driver, "Driver from inline config mismatch")

	driverNotFound := GetNetworkAttachmentDefinitionDriver("nonexistentns", "nonexistentnad")
	assert.Equal(t, "", driverNotFound, "Expected empty driver for non-existent NAD")
}

func TestGetNetworkAttachmentDefinitionDriver_MoreCases(t *testing.T) {
	InitializeNetworkAttachmentDefinitionCache()
	defer InitializeNetworkAttachmentDefinitionCache()

	tests := []struct {
		name           string
		nadNamespace   string
		nadName        string
		nadConfig      string
		expectedDriver string
		addToCache     bool
	}{
		{
			name:           "Valid bridge config inline",
			nadNamespace:   "testns",
			nadName:        "nad-bridge",
			nadConfig:      `{"cniVersion": "0.3.1", "name": "mybridge", "type": "bridge"}`,
			expectedDriver: "bridge",
			addToCache:     true,
		},
		{
			name:           "Valid macvlan config inline",
			nadNamespace:   "testns",
			nadName:        "nad-macvlan",
			nadConfig:      `{"cniVersion": "0.3.1", "name": "mymacvlan", "type": "macvlan"}`,
			expectedDriver: "macvlan",
			addToCache:     true,
		},
		{
			name:           "Config with no type field",
			nadNamespace:   "testns",
			nadName:        "nad-notype",
			nadConfig:      `{"cniVersion": "0.3.1", "name": "notype"}`,
			expectedDriver: "",
			addToCache:     true,
		},
		{
			name:           "Invalid JSON config",
			nadNamespace:   "testns",
			nadName:        "nad-invalidjson",
			nadConfig:      `{"cniVersion": "0.3.1", "name": "invalidjson", type: "oops"}`,
			expectedDriver: "",
			addToCache:     true,
		},
		{
			name:           "NAD not in cache",
			nadNamespace:   "testns",
			nadName:        "nad-notincache",
			nadConfig:      "",
			expectedDriver: "",
			addToCache:     false,
		},
		{
			name:           "Config references a file (cannot test file reading unitarily)",
			nadNamespace:   "testns",
			nadName:        "nad-fileconfig",
			nadConfig:      "",
			expectedDriver: "",
			addToCache:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			/* Clear cache before each MoreCases subtest for isolation */
			InitializeNetworkAttachmentDefinitionCache()
			if tt.addToCache {
				definition := &netdefv1.NetworkAttachmentDefinition{
					ObjectMeta: metav1.ObjectMeta{
						Name:      tt.nadName,
						Namespace: tt.nadNamespace,
					},
					Spec: netdefv1.NetworkAttachmentDefinitionSpec{
						Config: tt.nadConfig,
					},
				}
				AddNetworkAttachmentDefinitionCache(definition)
			}

			driver := GetNetworkAttachmentDefinitionDriver(tt.nadNamespace, tt.nadName)
			assert.Equal(t, tt.expectedDriver, driver)
		})
	}
}
