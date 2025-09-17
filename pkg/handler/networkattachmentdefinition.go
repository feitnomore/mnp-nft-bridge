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
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"k8s.io/klog/v2"
)

/* Event: Added NetworkAttachmentDefinition */
func AddNetAttach(nad *netdefv1.NetworkAttachmentDefinition) bool {
	if !cache.NetworkAttachmentDefinitionExistsInCache(nad.Namespace, nad.Name) {
		klog.V(8).Infof("Network Attachment Definition added: %s in namespace: %s\n", nad.Name, nad.Namespace)
		cache.AddNetworkAttachmentDefinitionCache(nad)
		/* Need reconcile */
		return true
	}
	/* Doesn't need reconcile */
	return false
}

/* Event: Updated  NetworkAttachmentDefinition */
func UpdateNetAttach(nad *netdefv1.NetworkAttachmentDefinition) bool {
	if cache.NetworkAttachmentDefinitionExistsInCache(nad.Namespace, nad.Name) {
		klog.V(8).Infof("Network Attachment Definition updated: %s in namespace: %s\n", nad.Name, nad.Namespace)
		actualNad := cache.GetNetworkAttachmentDefinitionFromCache(nad.Namespace, nad.Name)
		if !reflect.DeepEqual(actualNad.Spec, nad.Spec) || !reflect.DeepEqual(actualNad.Labels, nad.Labels) || !reflect.DeepEqual(actualNad.Annotations, nad.Annotations) {
			klog.Infof("Definition changed, updating....")
			cache.DeleteNetworkAttachmentDefinitionFromCache(nad.Namespace, nad.Name)
			cache.AddNetworkAttachmentDefinitionCache(nad)
			/* Need reconcile */
			return true
		}
	} else {
		AddNetAttach(nad)
		/* Need reconcile */
		return true
	}
	/* Doesn't need reconcile */
	return false
}

/* Event: Deleted  NetworkAttachmentDefinition */
func DeleteNetAttach(nad *netdefv1.NetworkAttachmentDefinition) bool {
	klog.V(8).Infof("Network Attachment Definition deleted: %s in namespace: %s\n", nad.Name, nad.Namespace)
	cache.DeleteNetworkAttachmentDefinitionFromCache(nad.Namespace, nad.Name)
	/* Need reconcile */
	return true
}
