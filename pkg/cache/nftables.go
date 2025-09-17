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

	"k8s.io/klog/v2"
)

/* Map to store Rules */
type NftablesCache struct {
	sync.RWMutex
	IngressRules map[string]string
	EgressRules  map[string]string
}

var nftCache NftablesCache

/* Initialize the cache maps */
func InitializeNftablesCache() {
	klog.V(8).Infof("Initializing nft Cache...")
	nftCache = NftablesCache{
		IngressRules: make(map[string]string),
		EgressRules:  make(map[string]string),
	}
}

/* AddIngressRuleID adds a rule ID to the ingress rule cache */
func AddIngressRuleID(ruleID, chainName string) {
	klog.V(8).Infof("Adding Ingress Rule ID: %s for chain: %s", ruleID, chainName)
	nftCache.Lock()
	defer nftCache.Unlock()
	nftCache.IngressRules[ruleID] = chainName
}

/* GetIngressRuleIDs retrieves all ingress rule IDs from the cache */
func GetIngressRuleIDs() []string {
	klog.V(8).Infof("Getting all Ingress Rule IDs")
	nftCache.RLock()
	defer nftCache.RUnlock()
	ruleIDs := make([]string, 0, len(nftCache.IngressRules))
	for ruleID := range nftCache.IngressRules {
		ruleIDs = append(ruleIDs, ruleID)
	}
	return ruleIDs
}

/* DeleteIngressRuleID deletes a specific ingress rule ID from the cache */
func DeleteIngressRuleID(ruleID string) {
	klog.V(8).Infof("Deleting Ingress Rule ID: %s", ruleID)
	nftCache.Lock()
	defer nftCache.Unlock()
	delete(nftCache.IngressRules, ruleID)
}

/* CheckIngressRuleID checks if a specific ingress rule ID exists in the cache */
func CheckIngressRuleID(ruleID string) bool {
	klog.V(8).Infof("Checking Ingress Rule ID: %s", ruleID)
	nftCache.RLock()
	defer nftCache.RUnlock()
	_, ok := nftCache.IngressRules[ruleID]
	return ok
}

/* AddEgressRuleID adds a rule ID to the egress rule cache */
func AddEgressRuleID(ruleID, chainName string) {
	klog.V(8).Infof("Adding Egress Rule ID: %s for chain: %s", ruleID, chainName)
	nftCache.Lock()
	defer nftCache.Unlock()
	nftCache.EgressRules[ruleID] = chainName
}

/* GetEgressRuleIDs retrieves all egress rule IDs from the cache */
func GetEgressRuleIDs() []string {
	klog.V(8).Infof("Getting all Egress Rule IDs")
	nftCache.RLock()
	defer nftCache.RUnlock()
	ruleIDs := make([]string, 0, len(nftCache.EgressRules))
	for ruleID := range nftCache.EgressRules {
		ruleIDs = append(ruleIDs, ruleID)
	}
	return ruleIDs
}

/* DeleteEgressRuleID deletes a specific egress rule ID from the cache */
func DeleteEgressRuleID(ruleID string) {
	klog.V(8).Infof("Deleting Egress Rule ID: %s", ruleID)
	nftCache.Lock()
	defer nftCache.Unlock()
	delete(nftCache.EgressRules, ruleID)
}

/* CheckEgressRuleID checks if a specific egress rule ID exists in the cache */
func CheckEgressRuleID(ruleID string) bool {
	klog.V(8).Infof("Checking Egress Rule ID: %s", ruleID)
	nftCache.RLock()
	defer nftCache.RUnlock()
	_, ok := nftCache.EgressRules[ruleID]
	return ok
}
