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

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"k8s.io/klog/v2"
)

/* MultiNetworkPolicyCache represents a map for storing MultiNetworkPolicies. */
type MultiNetworkPolicyCache struct {
	sync.RWMutex
	Policies map[string]*multiv1beta1.MultiNetworkPolicy
}

var multiNetworkPolicyCache MultiNetworkPolicyCache

/* Initialize the cache maps */
func InitializeMultiNetworkPolicyCache() {
	klog.V(8).Infof("Initializing multiNetworkPolicyCache...")
	multiNetworkPolicyCache = MultiNetworkPolicyCache{
		Policies: make(map[string]*multiv1beta1.MultiNetworkPolicy),
	}
}

/* Adds a MultiNetworkPolicy to Cache */
func AddMultiNetworkPolicy(policy *multiv1beta1.MultiNetworkPolicy) {
	klog.V(8).Infof("Adding MultiNetworkPolicy...")
	multiNetworkPolicyCache.Lock()
	defer multiNetworkPolicyCache.Unlock()
	key := policy.Namespace + "/" + policy.Name
	multiNetworkPolicyCache.Policies[key] = policy
}

/* Get MultiNetworkPolicy from cache */
func GetMultiNetworkPolicyCache() *multiv1beta1.MultiNetworkPolicyList {
	klog.V(8).Infof("Getting MultiNetworkPolicy Cache...")
	var policyList multiv1beta1.MultiNetworkPolicyList
	multiNetworkPolicyCache.RLock()
	defer multiNetworkPolicyCache.RUnlock()
	for _, value := range multiNetworkPolicyCache.Policies {
		policyList.Items = append(policyList.Items, *value)
	}
	return &policyList
}

/* Get MultiNetworkPolicy from cache */
func GetNamespacedMultiNetworkPolicyCache(ns string) *multiv1beta1.MultiNetworkPolicyList {
	klog.V(8).Infof("Getting Namespaced MultiNetworkPolicy Cache...")
	var policyList multiv1beta1.MultiNetworkPolicyList
	multiNetworkPolicyCache.RLock()
	defer multiNetworkPolicyCache.RUnlock()
	for _, value := range multiNetworkPolicyCache.Policies {
		if value.Namespace == ns {
			policyList.Items = append(policyList.Items, *value)
		}
	}
	return &policyList
}

/* Delete Multinetwork Policy from cache */
func DeleteMultiNetworkPolicyFromCache(name string, namespace string) {
	klog.V(8).Infof("Deleting MultiNetworkPolicy from Cache...")
	multiNetworkPolicyCache.Lock()
	defer multiNetworkPolicyCache.Unlock()
	key := namespace + "/" + name
	delete(multiNetworkPolicyCache.Policies, key)
}

/* MultiNetworkPolicy Exists in Cache */
func MultiNetworkPolicyExistsInCache(namespace, name string) bool {
	klog.V(8).Infof("Checking if MultiNetworkPolicy exists in cache...")
	multiNetworkPolicyCache.RLock() // Use RLock for read-only operation
	defer multiNetworkPolicyCache.RUnlock()
	key := namespace + "/" + name
	_, exists := multiNetworkPolicyCache.Policies[key]
	return exists
}

/* MultiNetworkPolicy Exists in Cache */
func GetMultiNetworkPolicyFromCache(namespace, name string) *multiv1beta1.MultiNetworkPolicy {
	klog.V(8).Infof("Getting MultiNetworkPolicy from cache...")
	multiNetworkPolicyCache.RLock() // Use RLock for read-only operation
	defer multiNetworkPolicyCache.RUnlock()
	key := namespace + "/" + name
	policy := multiNetworkPolicyCache.Policies[key]
	return policy
}
