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

	"github.com/feitnomore/mnp-nft-bridge/pkg/cache"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

/* Event: Added Namespace */
func AddNamespace(namespace *v1.Namespace) bool {
	if !cache.NamespaceExistsInCache(namespace.Name) {
		cache.AddNamespaceCache(namespace)
		klog.V(8).Infof("Namespace added: %s\n", namespace.Name)
		klog.V(8).Infof("Namespace labels: %v \n", namespace.Labels)
		/* Need reconcile */
		return true
	}
	/* Doesn't need reconcile */
	return false
}

/* Event: Updated Namespace */
func UpdateNamespace(namespace *v1.Namespace) bool {
	if cache.NamespaceExistsInCache(namespace.Name) {
		klog.V(8).Infof("Namespace updated: %s\n", namespace.Name)
		klog.V(8).Infof("Namespace labels: %v \n", namespace.Labels)
		actualNamespace := cache.GetNamespaceFromCache(namespace.Name)
		if !reflect.DeepEqual(actualNamespace.Spec, namespace.Spec) || !reflect.DeepEqual(actualNamespace.Labels, namespace.Labels) {
			klog.Infof("Namespaced changed, updating....")
			cache.DeleteNamespaceFromCache(namespace.Name)
			cache.AddNamespaceCache(namespace)
			/* Need reconcile */
			return true
		}
	} else {
		AddNamespace(namespace)
		/* Need reconcile */
		return true
	}
	/* Doesn't need reconcile */
	return false
}

/* Event: Deleted Namespace */
func DeleteNamespace(namespace *v1.Namespace) bool {
	klog.V(8).Infof("Namespace deleted: %s\n", namespace.Name)
	cache.DeleteNamespaceFromCache(namespace.Name)
	klog.V(8).Infof("Deleting namespace from cache....")
	/* Need reconcile */
	return true
}
