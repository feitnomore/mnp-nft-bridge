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
	"sync"

	"github.com/feitnomore/mnp-nft-bridge/pkg/types" // Certifique-se que types.PodChainMetadata é importado
	"k8s.io/klog/v2"
)

/* NftPodChainMetadataCache holds metadata for pod-specific nftables chains.
 * The key is a unique identifier for the chain, e.g., chainSuffix + "_" + chainType.
 */
type NftPodChainMetadataCache struct {
	sync.RWMutex
	Metadata map[string]types.PodChainMetadata
}

var nftPodChainMetadataCache NftPodChainMetadataCache

/* InitializeNftPodChainMetadataCache initializes the cache for nftables pod chain metadata. */
func InitializeNftPodChainMetadataCache() {
	klog.V(8).Infof("Initializing nftPodChainMetadataCache...")
	nftPodChainMetadataCache = NftPodChainMetadataCache{
		Metadata: make(map[string]types.PodChainMetadata),
	}
}

/* AddOrUpdateNftPodChainMetadata adds or updates metadata for a given chain key. */
func AddOrUpdateNftPodChainMetadata(key string, meta types.PodChainMetadata) {
	nftPodChainMetadataCache.Lock()
	defer nftPodChainMetadataCache.Unlock()
	nftPodChainMetadataCache.Metadata[key] = meta
	klog.V(5).Infof("Added/Updated metadata in nftPodChainMetadataCache for key: %s with PolicyName: %s/%s, PolicyIngressRuleCount: %d, PolicyEgressRuleCount: %d, IsIsolationChain:%t, PolicyRuleCount:%d",
		key, meta.PolicyNamespace, meta.PolicyName, meta.PolicyIngressRuleCount, meta.PolicyEgressRuleCount, meta.IsIsolationChain, meta.PolicyRuleCount)
}

/* GetNftPodChainMetadata retrieves metadata for a given chain key. */
func GetNftPodChainMetadata(key string) (types.PodChainMetadata, bool) {
	nftPodChainMetadataCache.RLock()
	defer nftPodChainMetadataCache.RUnlock()
	meta, exists := nftPodChainMetadataCache.Metadata[key]
	if exists {
		klog.V(8).Infof("GetNftPodChainMetadata: Found metadata for key %s: PolicyName: %s/%s", key, meta.PolicyNamespace, meta.PolicyName)
	} else {
		klog.V(8).Infof("GetNftPodChainMetadata: No metadata found for key %s", key)
	}
	return meta, exists
}

/* DeleteNftPodChainMetadata removes metadata for a given chain key. */
func DeleteNftPodChainMetadata(key string) {
	nftPodChainMetadataCache.Lock()
	defer nftPodChainMetadataCache.Unlock()

	if meta, exists := nftPodChainMetadataCache.Metadata[key]; exists {
		delete(nftPodChainMetadataCache.Metadata, key)
		klog.V(4).Infof("Deleted metadata from nftPodChainMetadataCache for key: %s (was for Policy: %s/%s, Pod: %s/%s)", key, meta.PolicyNamespace, meta.PolicyName, meta.PodNamespace, meta.PodName)
	} else {
		klog.V(5).Infof("DeleteNftPodChainMetadata: Attempted to delete metadata for non-existent key: %s", key)
	}
}

/* GetAllNftPodChainMetadataKeys returns a slice of all keys currently in the cache. */
func GetAllNftPodChainMetadataKeys() []string {
	nftPodChainMetadataCache.RLock()
	defer nftPodChainMetadataCache.RUnlock()
	keys := make([]string, 0, len(nftPodChainMetadataCache.Metadata))
	for k := range nftPodChainMetadataCache.Metadata {
		keys = append(keys, k)
	}
	klog.V(8).Infof("GetAllNftPodChainMetadataKeys: Returning %d keys: %v", len(keys), keys)
	return keys
}
