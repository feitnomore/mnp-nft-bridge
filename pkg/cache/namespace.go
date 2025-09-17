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
	"fmt"
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
)

/* NamespaceCache represents a map for storing namespaces */
type NamespaceCache struct {
	sync.RWMutex
	Namespaces map[string]*v1.Namespace
}

var namespaceCache NamespaceCache

/* Initialize the cache maps */
func InitializeNamespaceCache() {
	klog.V(8).Infof("Initializing namespaceCache...")
	namespaceCache = NamespaceCache{
		Namespaces: make(map[string]*v1.Namespace),
	}
}

/* AddNamespaceCache adds a Namespace to the cache */
func AddNamespaceCache(namespace *v1.Namespace) {
	klog.V(8).Infof("Adding Namespace...")
	namespaceCache.Lock()
	defer namespaceCache.Unlock()
	key := namespace.Name
	namespaceCache.Namespaces[key] = namespace
}

/* Get namespaces from cache */
func GetNamespaceCache() *v1.NamespaceList {
	klog.V(8).Infof("Getting Namespace Cache...")
	namespaceCache.RLock()
	defer namespaceCache.RUnlock()
	var nsList v1.NamespaceList
	for _, value := range namespaceCache.Namespaces {
		nsList.Items = append(nsList.Items, *value)
	}
	return &nsList
}

/* Get specific namespace from cache */
func GetNamespaceFromCache(name string) *v1.Namespace {
	klog.V(8).Infof("Getting Namespace...")
	namespaceCache.RLock()
	defer namespaceCache.RUnlock()
	key := name
	namespace := namespaceCache.Namespaces[key]
	return namespace
}

/* Delete Namespace from cache */
func DeleteNamespaceFromCache(name string) {
	klog.V(8).Infof("Deleting Namespace from Cache...")
	namespaceCache.Lock()
	defer namespaceCache.Unlock()
	key := name
	delete(namespaceCache.Namespaces, key)
}

/* Namespace Exists in Cache */
func NamespaceExistsInCache(namespace string) bool {
	klog.V(8).Infof("Checking if Namespace exists in cache...")
	namespaceCache.RLock() // Use RLock for read-only operation
	defer namespaceCache.RUnlock()
	_, exists := namespaceCache.Namespaces[namespace]
	return exists
}

/* Namespace Matches Selector */
func matchesNamespaceLabels(namespace *v1.Namespace, selector map[string]string) bool {
	policyNamespaceSelector := labels.Set(selector).AsSelectorPreValidated()
	if !policyNamespaceSelector.Matches(labels.Set(namespace.Labels)) {
		/* Namespace did not match selector */
		klog.V(8).Infof("Namespace: %s did not match policy selector....", namespace.Name)
		return false
	}
	return true
}

/* Get Namespaces by Labels */
func GetNamespacesByLabels(labels map[string]string) (*v1.NamespaceList, error) {
	namespaceCache := GetNamespaceCache()
	if namespaceCache == nil {
		return nil, fmt.Errorf("namespace cache not initialized")
	}

	var matchingNamespaces v1.NamespaceList
	for _, ns := range namespaceCache.Items {
		klog.V(8).Infof("GetNamespacesByLabels ns: %v", ns.Name)
		if matchesNamespaceLabels(&ns, labels) {
			klog.V(8).Infof("GetNamespacesByLabels: MATCHED")
			matchingNamespaces.Items = append(matchingNamespaces.Items, ns)
		}
	}

	return &matchingNamespaces, nil
}
