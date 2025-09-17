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
	"sort"
	"testing"

	"github.com/feitnomore/mnp-nft-bridge/pkg/types"
)

func TestNftPodChainMetadataCache(t *testing.T) {
	/* Test case 1: Initialize the cache */
	InitializeNftPodChainMetadataCache()
	if nftPodChainMetadataCache.Metadata == nil {
		t.Errorf("InitializeNftPodChainMetadataCache: Metadata map is nil after initialization")
	}
	if len(nftPodChainMetadataCache.Metadata) != 0 {
		t.Errorf("InitializeNftPodChainMetadataCache: Metadata map should be empty after initialization, got %d items", len(nftPodChainMetadataCache.Metadata))
	}

	/* Sample metadata */
	meta1 := types.PodChainMetadata{
		PolicyName:             "policy-a",
		PolicyNamespace:        "ns-a",
		PodName:                "pod-1",
		PodNamespace:           "ns-a",
		PodMac:                 "00:11:22:33:44:55",
		ChainType:              types.IngressChainType,
		FullChainName:          types.IngressChain + "_suffix1",
		ChainSuffix:            "suffix1",
		PolicyIngressRuleCount: 1,
		PolicyEgressRuleCount:  0,
	}
	key1 := "suffix1_" + types.IngressChainType

	meta2 := types.PodChainMetadata{
		PolicyName:             "policy-b",
		PolicyNamespace:        "ns-b",
		PodName:                "pod-2",
		PodNamespace:           "ns-b",
		PodMac:                 "AA:BB:CC:DD:EE:FF",
		ChainType:              types.EgressChainType,
		FullChainName:          types.EgressChain + "_suffix2",
		ChainSuffix:            "suffix2",
		PolicyIngressRuleCount: 0,
		PolicyEgressRuleCount:  2,
	}
	key2 := "suffix2_" + types.EgressChainType

	/* Test case 2: Add new metadata */
	AddOrUpdateNftPodChainMetadata(key1, meta1)
	if len(nftPodChainMetadataCache.Metadata) != 1 {
		t.Errorf("AddOrUpdateNftPodChainMetadata (new): Expected 1 item in cache, got %d", len(nftPodChainMetadataCache.Metadata))
	}
	cachedMeta1, exists1 := nftPodChainMetadataCache.Metadata[key1]
	if !exists1 {
		t.Errorf("AddOrUpdateNftPodChainMetadata (new): Key '%s' not found in cache", key1)
	}
	if !reflect.DeepEqual(cachedMeta1, meta1) {
		t.Errorf("AddOrUpdateNftPodChainMetadata (new): Metadata for key '%s' does not match. Got %+v, Expected %+v", key1, cachedMeta1, meta1)
	}

	/* Test case 3: Get existing metadata */
	retrievedMeta1, existsGet1 := GetNftPodChainMetadata(key1)
	if !existsGet1 {
		t.Errorf("GetNftPodChainMetadata (existing): Expected key '%s' to exist, but it doesn't", key1)
	}
	if !reflect.DeepEqual(retrievedMeta1, meta1) {
		t.Errorf("GetNftPodChainMetadata (existing): Metadata for key '%s' does not match. Got %+v, Expected %+v", key1, retrievedMeta1, meta1)
	}

	/* Test case 4: Update existing metadata */
	updatedMeta1 := meta1
	updatedMeta1.PolicyIngressRuleCount = 2
	AddOrUpdateNftPodChainMetadata(key1, updatedMeta1)
	if len(nftPodChainMetadataCache.Metadata) != 1 {
		t.Errorf("AddOrUpdateNftPodChainMetadata (update): Expected 1 item in cache after update, got %d", len(nftPodChainMetadataCache.Metadata))
	}
	cachedUpdatedMeta1, existsUpdated1 := nftPodChainMetadataCache.Metadata[key1]
	if !existsUpdated1 {
		t.Errorf("AddOrUpdateNftPodChainMetadata (update): Key '%s' not found in cache after update", key1)
	}
	if !reflect.DeepEqual(cachedUpdatedMeta1, updatedMeta1) {
		t.Errorf("AddOrUpdateNftPodChainMetadata (update): Metadata for key '%s' not updated correctly. Got %+v, Expected %+v", key1, cachedUpdatedMeta1, updatedMeta1)
	}

	/* Test case 5: Get non-existent metadata */
	_, existsGetNonExistent := GetNftPodChainMetadata("non_existent_key")
	if existsGetNonExistent {
		t.Errorf("GetNftPodChainMetadata (non-existent): Expected key 'non_existent_key' to not exist, but it does")
	}

	/* Test case 6: Add another metadata item for GetAllNftPodChainMetadataKeys test */
	AddOrUpdateNftPodChainMetadata(key2, meta2)
	if len(nftPodChainMetadataCache.Metadata) != 2 {
		t.Errorf("AddOrUpdateNftPodChainMetadata (second item): Expected 2 items in cache, got %d", len(nftPodChainMetadataCache.Metadata))
	}

	/* Test case 7: Get all keys (with items) */
	allKeys := GetAllNftPodChainMetadataKeys()
	expectedKeys := []string{key1, key2}
	sort.Strings(allKeys)      /* Sort for deterministic comparison */
	sort.Strings(expectedKeys) /* Sort for deterministic comparison */
	if len(allKeys) != 2 {
		t.Errorf("GetAllNftPodChainMetadataKeys: Expected 2 keys, got %d", len(allKeys))
	}
	if !reflect.DeepEqual(allKeys, expectedKeys) {
		t.Errorf("GetAllNftPodChainMetadataKeys: Keys do not match. Got %v, Expected %v", allKeys, expectedKeys)
	}

	/* Test case 8: Delete existing metadata (key2) */
	DeleteNftPodChainMetadata(key2)
	if len(nftPodChainMetadataCache.Metadata) != 1 {
		t.Errorf("DeleteNftPodChainMetadata (existing): Expected 1 item in cache after deleting key2, got %d", len(nftPodChainMetadataCache.Metadata))
	}
	if _, exists := nftPodChainMetadataCache.Metadata[key2]; exists {
		t.Errorf("DeleteNftPodChainMetadata (existing): Key '%s' still exists in cache after deletion", key2)
	}

	/* Test case 9: Delete non-existent metadata (should not panic or change count) */
	DeleteNftPodChainMetadata("non_existent_key_for_delete")
	if len(nftPodChainMetadataCache.Metadata) != 1 {
		t.Errorf("DeleteNftPodChainMetadata (non-existent): Cache size changed after attempting to delete non-existent key. Expected 1, got %d", len(nftPodChainMetadataCache.Metadata))
	}

	/* Test case 10: Delete the last remaining metadata (key1) */
	DeleteNftPodChainMetadata(key1)
	if len(nftPodChainMetadataCache.Metadata) != 0 {
		t.Errorf("DeleteNftPodChainMetadata (last item): Expected 0 items in cache after deleting key1, got %d", len(nftPodChainMetadataCache.Metadata))
	}
	if _, exists := nftPodChainMetadataCache.Metadata[key1]; exists {
		t.Errorf("DeleteNftPodChainMetadata (last item): Key '%s' still exists in cache after deletion", key1)
	}

	/* Test case 11: Get all keys (after all deletions / empty cache) */
	emptyKeys := GetAllNftPodChainMetadataKeys()
	if len(emptyKeys) != 0 {
		t.Errorf("GetAllNftPodChainMetadataKeys (empty): Expected 0 keys for empty cache, got %d", len(emptyKeys))
	}
}
