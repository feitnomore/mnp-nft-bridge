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

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
)

/* Map to store Pods */
type PodCache struct {
	sync.RWMutex
	Pods map[string]*v1.Pod
}

var podCache PodCache

/* Initialize the cache maps */
func InitializePodCache() {
	klog.V(8).Infof("Initializing podCache...")
	podCache = PodCache{
		Pods: make(map[string]*v1.Pod),
	}
}

func AddPodToCache(pod *v1.Pod) {
	podCache.Lock()
	defer podCache.Unlock()
	key := pod.Namespace + "/" + pod.Name
	podCache.Pods[key] = pod
	klog.V(2).Infof("Pod %s added/updated in cache. MAC from status: %s", key, getMacFromStatusForCache(pod))
}

/* Helper function for cache (avoid cyclic dependency if getMacFromStatus was complex and in utils) */
func getMacFromStatusForCache(pod *v1.Pod) string {
	if pod == nil || pod.Annotations == nil {
		return "N/A (nil pod or annotations)"
	}
	netStatusRaw, ok := pod.Annotations[netdefv1.NetworkStatusAnnot]
	if !ok || netStatusRaw == "" {
		return "N/A (no network status annot)"
	}
	return netStatusRaw
}

/* GetPodFromCache gets a specific Pod from the cache */
func GetPodFromCache(namespace, name string) *v1.Pod {
	klog.V(8).Infof("Getting Pod...")
	podCache.RLock()
	defer podCache.RUnlock()
	key := namespace + "/" + name
	pod := podCache.Pods[key]
	return pod
}

/* Get Pods from cache */
func GetPodsCache() *v1.PodList {
	klog.V(8).Infof("Getting Pod Cache...")
	var podList v1.PodList
	podCache.RLock()
	defer podCache.RUnlock()
	for _, value := range podCache.Pods {
		podList.Items = append(podList.Items, *value)
	}
	return &podList
}

/* Get Namespaced Pods from cache */
func GetNamespacedPodsCache(ns string) *v1.PodList {
	klog.V(8).Infof("Getting Pod Cache...")
	var podList v1.PodList
	podCache.RLock()
	defer podCache.RUnlock()
	for _, value := range podCache.Pods {
		if value.Namespace == ns {
			podList.Items = append(podList.Items, *value)
		}
	}
	return &podList
}

/* Get full cache */
func GetFullPodCache() *PodCache {
	return &podCache
}

/* Delete a Pod from Cache */
func DeletePodFromCache(namespace, name string) {
	klog.V(8).Infof("Deleting Pod from Cache...")
	podCache.Lock()
	defer podCache.Unlock()
	key := namespace + "/" + name
	delete(podCache.Pods, key)
}

/* Pod Exists in Cache */
func PodExistsInCache(namespace, name string) bool {
	klog.V(8).Infof("Checking if Pod exists in cache...")
	podCache.RLock()
	defer podCache.RUnlock()
	key := namespace + "/" + name
	_, exists := podCache.Pods[key]
	return exists
}

/* Pod Matches Selector  */
func matchesPodLabels(pod *v1.Pod, selector map[string]string) bool {
	policyPodSelector := labels.Set(selector).AsSelectorPreValidated()
	if !policyPodSelector.Matches(labels.Set(pod.Labels)) {
		/* Pod did not match selector */
		klog.Infof("Pod: %s did not match policy selector....", pod.Name)
		return false
	}
	return true
}

/* Gets pods by labels */
func GetPodsByLabels(labels map[string]string) (*v1.PodList, error) {
	podCache := GetFullPodCache()
	if podCache == nil {
		return nil, fmt.Errorf("pod cache not initialized")
	}

	podCache.RLock()
	defer podCache.RUnlock()

	var matchingPods v1.PodList
	for _, pod := range podCache.Pods {
		klog.V(8).Infof("GetPodsByLabels pod: %v", pod.Name)
		if matchesPodLabels(pod, labels) {
			klog.V(8).Infof("GetPodsByLabels: MATCHED")
			matchingPods.Items = append(matchingPods.Items, *pod)
		}
	}

	return &matchingPods, nil
}

/* Gets pods by labels on a given namespace */
func GetNamespacedPodsByLabels(namespace string, labels map[string]string) (*v1.PodList, error) {
	podCache := GetFullPodCache()
	if podCache == nil {
		return nil, fmt.Errorf("pod cache not initialized")
	}

	podCache.RLock()
	defer podCache.RUnlock()

	var matchingPods v1.PodList
	for _, pod := range podCache.Pods {
		if pod.Namespace == namespace && matchesPodLabels(pod, labels) {
			matchingPods.Items = append(matchingPods.Items, *pod)
		}
	}

	return &matchingPods, nil
}

/* Gets pods from a given namespace */
func GetNamespacedPods(namespace string) (*v1.PodList, error) {
	podCache := GetFullPodCache()
	if podCache == nil {
		return nil, fmt.Errorf("pod cache not initialized")
	}

	podCache.RLock()
	defer podCache.RUnlock()

	var matchingPods v1.PodList
	for _, pod := range podCache.Pods {
		if pod.Namespace == namespace {
			matchingPods.Items = append(matchingPods.Items, *pod)
		}
	}

	return &matchingPods, nil
}
