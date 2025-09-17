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

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	"github.com/feitnomore/mnp-nft-bridge/pkg/cache"
	"github.com/feitnomore/mnp-nft-bridge/pkg/utils"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

/* Event: Added  Pod */
func AddPod(pod *v1.Pod) bool {
	if utils.PodMultiNetwork(pod) {
		if !cache.PodExistsInCache(pod.Namespace, pod.Name) {
			klog.V(2).Infof("Pod add event: %s/%s. Adding to cache. MAC from status: %s", pod.Namespace, pod.Name, getMacFromStatus(pod)) // Log aumentado e adiciona MAC
			cache.AddPodToCache(pod)
			/* Need reconcile */
			return true
		}
		klog.V(4).Infof("Pod add event: %s/%s. Pod already exists in cache. MAC from status: %s", pod.Namespace, pod.Name, getMacFromStatus(pod))
	}
	return false
}

// Função helper para loggar o MAC (pode ser mais elaborada)
func getMacFromStatus(pod *v1.Pod) string {
	if pod == nil || pod.Annotations == nil {
		return "N/A (nil pod or annotations)"
	}
	netStatusRaw, ok := pod.Annotations[netdefv1.NetworkStatusAnnot]
	if !ok || netStatusRaw == "" {
		return "N/A (no network status annot)"
	}
	return netStatusRaw
}

/* Event: Updated  Pod */
func UpdatePod(pod *v1.Pod) bool {
	/* We only work with pods that have multinetwork */
	if utils.PodMultiNetwork(pod) {
		if cache.PodExistsInCache(pod.Namespace, pod.Name) {
			klog.V(8).Infof("Pod updated: %s in namespace: %s\n", pod.Name, pod.Namespace)
			actualPod := cache.GetPodFromCache(pod.Namespace, pod.Name)
			/* Get old and new network status */
			oldNetStatusAnnotation := actualPod.Annotations[netdefv1.NetworkStatusAnnot]
			newNetStatusAnnotation := pod.Annotations[netdefv1.NetworkStatusAnnot]

			if !reflect.DeepEqual(actualPod.Spec, pod.Spec) || !reflect.DeepEqual(actualPod.Labels, pod.Labels) || actualPod.Status.Phase != pod.Status.Phase || oldNetStatusAnnotation != newNetStatusAnnotation {
				klog.V(4).Infof("Pod %s/%s changed (Spec, Labels, Phase, or NetworkStatus). Updating cache.", pod.Namespace, pod.Name)
				klog.V(5).Infof("Old Network Status: %s", oldNetStatusAnnotation)
				klog.V(5).Infof("New Network Status: %s", newNetStatusAnnotation)
				cache.DeletePodFromCache(pod.Namespace, pod.Name)
				cache.AddPodToCache(pod)
				/* Need reconcile */
				return true
			}
		} else {
			AddPod(pod)
			/* Need reconcile */
			return true
		}
	}
	/* Doesn't need reconcile */
	return false
}

/* Event: Deleted  Pod */
func DeletePod(pod *v1.Pod) bool {
	/* We only work with pods that have multinetwork */
	if utils.PodMultiNetwork(pod) {
		klog.V(8).Infof("Pod deleted: %s in namespace: %s\n", pod.Name, pod.Namespace)
		cache.DeletePodFromCache(pod.Namespace, pod.Name)
		klog.V(8).Infof("Deleting pod from cache....")
		/* Need reconcile */
		return true
	}
	/* Doesn't need reconcile */
	return false
}
