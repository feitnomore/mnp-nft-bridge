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
	"encoding/json"
	"sync"

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"k8s.io/klog/v2"
)

/* NetworkAttachmentDefinitionCache represents a map for storing NetworkAttachmentDefinitions. */
type NetworkAttachmentDefinitionCache struct {
	sync.RWMutex
	Definitions map[string]*netdefv1.NetworkAttachmentDefinition
}

var networkAttachmentDefinitionCache NetworkAttachmentDefinitionCache

/* Local struct to parse only the 'type' field of the CNI config JSON */
type cniConfig struct {
	Type string `json:"type"`
}

/* Initialize the cache maps */
func InitializeNetworkAttachmentDefinitionCache() {
	klog.V(8).Infof("Initializing networkAttachmentDefinitionCache...")
	networkAttachmentDefinitionCache = NetworkAttachmentDefinitionCache{
		Definitions: make(map[string]*netdefv1.NetworkAttachmentDefinition),
	}
}

/* AddNetworkPolicy adds a NetworkPolicy to the cache */
func AddNetworkAttachmentDefinitionCache(definition *netdefv1.NetworkAttachmentDefinition) {
	klog.V(8).Infof("Adding NetworkAttachmentDefinition...")
	networkAttachmentDefinitionCache.Lock()
	defer networkAttachmentDefinitionCache.Unlock()
	key := definition.Namespace + "/" + definition.Name
	networkAttachmentDefinitionCache.Definitions[key] = definition
}

/* Get NetworkAttachmentDefinition from cache */
func GetNetworkAttachmentDefinitionCache() *netdefv1.NetworkAttachmentDefinitionList {
	klog.V(8).Infof("Getting Namespace Cache...")
	var networkList netdefv1.NetworkAttachmentDefinitionList
	networkAttachmentDefinitionCache.RLock()
	defer networkAttachmentDefinitionCache.RUnlock()
	for _, value := range networkAttachmentDefinitionCache.Definitions {
		networkList.Items = append(networkList.Items, *value)
	}
	return &networkList
}

/* Get NetworkAttachmentDefinition cache */
func GetNamespacedNetworkAttachmentDefinitionCache(ns string) *netdefv1.NetworkAttachmentDefinitionList {
	klog.V(8).Infof("Getting Namespace Cache...")
	var networkList netdefv1.NetworkAttachmentDefinitionList
	networkAttachmentDefinitionCache.RLock()
	defer networkAttachmentDefinitionCache.RUnlock()
	for _, value := range networkAttachmentDefinitionCache.Definitions {
		if value.Namespace == ns {
			networkList.Items = append(networkList.Items, *value)
		}
	}
	return &networkList
}

/* Get NetworkAttachmentDefinition driver */
func GetNetworkAttachmentDefinitionDriver(namespace, name string) string {
	klog.V(8).Infof("Getting Network Definition Driver for %s/%s...", namespace, name)
	networkAttachmentDefinitionCache.RLock()
	defer networkAttachmentDefinitionCache.RUnlock()
	key := namespace + "/" + name
	nad, ok := networkAttachmentDefinitionCache.Definitions[key]
	if !ok {
		klog.V(5).Infof("NAD %s not found in cache.", key)
		return ""
	}

	if nad.Spec.Config == "" {
		klog.V(5).Infof("NAD %s has an empty spec.config.", key)
		return ""
	}

	/* Parse the JSON directly to get the type.
	 * This approach is robust and doesn't rely on external libraries for this simple task.
	 */
	var conf cniConfig
	if err := json.Unmarshal([]byte(nad.Spec.Config), &conf); err != nil {
		klog.Errorf("Error unmarshalling spec.config for NAD %s: %v. Config was: %s", key, err, nad.Spec.Config)
		return ""
	}

	klog.V(7).Infof("Successfully parsed CNI driver type '%s' from NAD %s spec.config.", conf.Type, key)
	return conf.Type
}

/* Get NetworkAttachmentDefinition from cache */
func GetNetworkAttachmentDefinitionFromCache(namespace, name string) *netdefv1.NetworkAttachmentDefinition {
	klog.V(8).Infof("Getting Network Definition From Cache...")
	networkAttachmentDefinitionCache.RLock()
	defer networkAttachmentDefinitionCache.RUnlock()
	key := namespace + "/" + name
	nad := networkAttachmentDefinitionCache.Definitions[key]
	return nad
}

/* NetworkAttachmentDefinition Exists in Cache */
func NetworkAttachmentDefinitionExistsInCache(namespace, name string) bool {
	klog.V(8).Infof("Checking if NetworkAttachmentDefinition exists in cache...")
	networkAttachmentDefinitionCache.RLock()
	defer networkAttachmentDefinitionCache.RUnlock()
	key := namespace + "/" + name
	_, exists := networkAttachmentDefinitionCache.Definitions[key]
	return exists
}

/* Delete NetworkAttachmentDefinition from cache */
func DeleteNetworkAttachmentDefinitionFromCache(namespace, name string) {
	klog.V(8).Infof("Deleting NetworkAttachmentDefinition from Cache...")
	networkAttachmentDefinitionCache.Lock()
	defer networkAttachmentDefinitionCache.Unlock()
	key := namespace + "/" + name
	delete(networkAttachmentDefinitionCache.Definitions, key)
}
