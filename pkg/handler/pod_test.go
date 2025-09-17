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
	"testing"

	"github.com/feitnomore/mnp-nft-bridge/pkg/cache"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	networkStatusAnnot = netdefv1.NetworkStatusAnnot
	networksAnnot      = netdefv1.NetworkAttachmentAnnot
)

/* Helper to create a basic pod for testing */
func testPod(namespace, name string, labels, annotations map[string]string) *v1.Pod {
	finalAnnotations := make(map[string]string)
	for k, v := range annotations {
		finalAnnotations[k] = v
	}

	if _, ok := finalAnnotations[networksAnnot]; !ok {
		finalAnnotations[networksAnnot] = "default/dummy-net1, default/dummy-net2"
	}
	if _, ok := finalAnnotations[networkStatusAnnot]; !ok {
		finalAnnotations[networkStatusAnnot] = `[{"name":"default/dummy-net1", "interface":"eth0"}, {"name":"default/dummy-net2", "interface":"net1"}]`
	}

	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: finalAnnotations,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{{Name: "test-container", Image: "test-image"}},
		},
		Status: v1.PodStatus{Phase: v1.PodRunning},
	}
}

func TestAddPodHandler(t *testing.T) {
	cache.InitializePodCache()
	defer cache.InitializePodCache()

	pod1Labels := map[string]string{"app": "testapp1"}
	pod1Annots := map[string]string{networkStatusAnnot: `[{"name":"net1"},{"name":"net2","mac":"00:00:00:00:00:01"}]`}
	pod1 := testPod("default", "pod1", pod1Labels, pod1Annots)

	pod2Labels := map[string]string{"app": "testapp2"}
	pod2Annots := map[string]string{networkStatusAnnot: `[{"name":"net1"},{"name":"net2","mac":"00:00:00:00:00:01"}]`}
	pod2 := testPod("newns", "pod2", pod2Labels, pod2Annots)

	podNoMultiNetAnnots := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-no-multinet", Namespace: "default"},
	}

	tests := []struct {
		name            string
		podToAdd        *v1.Pod
		setupCache      func()
		expectAdd       bool
		expectReconcile bool
	}{
		{
			name:            "Add new pod with multinetwork on default namespace",
			podToAdd:        pod1,
			setupCache:      func() { cache.InitializePodCache() },
			expectAdd:       true,
			expectReconcile: true,
		},
		{
			name:            "Add new pod with multinetwork on newns namespace",
			podToAdd:        pod2,
			setupCache:      func() { cache.InitializePodCache() },
			expectAdd:       true,
			expectReconcile: true,
		},
		{
			name:     "Add pod that already exists (no change)",
			podToAdd: pod1,
			setupCache: func() {
				cache.InitializePodCache()
				cache.AddPodToCache(pod1)
			},
			expectAdd:       false,
			expectReconcile: false,
		},
		{
			name:            "Add pod without multinetwork annotation",
			podToAdd:        podNoMultiNetAnnots,
			setupCache:      func() { cache.InitializePodCache() },
			expectAdd:       false,
			expectReconcile: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupCache()

			reconcileNeeded := AddPod(tt.podToAdd)
			assert.Equal(t, tt.expectReconcile, reconcileNeeded)

			if tt.expectAdd {
				cachedPod := cache.GetPodFromCache(tt.podToAdd.Namespace, tt.podToAdd.Name)
				require.NotNil(t, cachedPod, "Pod should be in cache")
				assert.True(t, reflect.DeepEqual(tt.podToAdd.Labels, cachedPod.Labels))
				assert.True(t, reflect.DeepEqual(tt.podToAdd.Annotations, cachedPod.Annotations))
			} else if tt.podToAdd.Name == podNoMultiNetAnnots.Name {
				assert.False(t, cache.PodExistsInCache(tt.podToAdd.Namespace, tt.podToAdd.Name), "Pod without multinet should not be in cache")
			}
		})
	}
}

func TestUpdatePodHandler(t *testing.T) {
	cache.InitializePodCache()
	defer cache.InitializePodCache()

	baseLabels := map[string]string{"app": "testapp", "version": "v1"}
	baseAnnots := map[string]string{
		networksAnnot:      "net1,net2",
		networkStatusAnnot: `[{"name":"net1","mac":"aa:bb:cc:dd:ee:00"},{"name":"net2","mac":"aa:bb:cc:dd:ee:11"}]`,
	}
	initialPod := testPod("default", "pod-update", baseLabels, baseAnnots)
	initialPod.Status.Phase = v1.PodRunning

	tests := []struct {
		name            string
		podInCache      *v1.Pod
		podToUpdate     *v1.Pod
		expectUpdate    bool
		expectReconcile bool
	}{
		{
			name:            "Update pod that does not exist in cache (behaves like Add)",
			podInCache:      nil,
			podToUpdate:     testPod("default", "newpod", baseLabels, baseAnnots),
			expectUpdate:    true,
			expectReconcile: true,
		},
		{
			name:            "Update pod with no relevant changes",
			podInCache:      initialPod.DeepCopy(),
			podToUpdate:     initialPod.DeepCopy(),
			expectUpdate:    false,
			expectReconcile: false,
		},
		{
			name:       "Update pod with label change",
			podInCache: initialPod.DeepCopy(),
			podToUpdate: func() *v1.Pod {
				p := initialPod.DeepCopy()
				p.Labels = map[string]string{"app": "testapp", "version": "v2"}
				return p
			}(),
			expectUpdate:    true,
			expectReconcile: true,
		},
		{
			name:       "Update pod with annotation change (network status)",
			podInCache: initialPod.DeepCopy(),
			podToUpdate: func() *v1.Pod {
				p := initialPod.DeepCopy()
				p.Annotations = map[string]string{
					networksAnnot:      "net1,net2",
					networkStatusAnnot: `[{"name":"net1","mac":"aa:bb:cc:dd:ee:00"},{"name":"net2","mac":"FF:FF:FF:FF:FF:FF"}]`,
				}
				return p
			}(),
			expectUpdate:    true,
			expectReconcile: true,
		},
		{
			name:       "Update pod with phase change",
			podInCache: initialPod.DeepCopy(),
			podToUpdate: func() *v1.Pod {
				p := initialPod.DeepCopy()
				p.Status.Phase = v1.PodFailed
				return p
			}(),
			expectUpdate:    true,
			expectReconcile: true,
		},
		{
			name:       "Update pod, but it loses multinetwork annotation (should be removed from cache)",
			podInCache: initialPod.DeepCopy(),
			podToUpdate: func() *v1.Pod {
				p := initialPod.DeepCopy()
				p.Annotations = map[string]string{"some-other": "value"}
				return p
			}(),
			expectUpdate:    false,
			expectReconcile: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.InitializePodCache()
			if tt.podInCache != nil {
				cache.AddPodToCache(tt.podInCache)
			}

			reconcileNeeded := UpdatePod(tt.podToUpdate)
			assert.Equal(t, tt.expectReconcile, reconcileNeeded)

			cachedPod := cache.GetPodFromCache(tt.podToUpdate.Namespace, tt.podToUpdate.Name)
			if tt.expectUpdate {
				require.NotNil(t, cachedPod, "Pod should be in cache after update")
				assert.True(t, reflect.DeepEqual(tt.podToUpdate.Labels, cachedPod.Labels))
				assert.True(t, reflect.DeepEqual(tt.podToUpdate.Annotations, cachedPod.Annotations))
				assert.Equal(t, tt.podToUpdate.Status.Phase, cachedPod.Status.Phase)
			} else {
				if tt.podInCache != nil && tt.podToUpdate.Name == tt.podInCache.Name {
					assert.True(t, reflect.DeepEqual(tt.podInCache, cachedPod), "Pod in cache should not have changed")
				} else if tt.podInCache == nil && tt.podToUpdate.Name != "newpod" {
					assert.Nil(t, cachedPod, "Pod should not be in cache if not updated/added")
				}
			}
		})
	}
}

func TestDeletePodHandler(t *testing.T) {
	cache.InitializePodCache()
	defer cache.InitializePodCache()

	pod1Labels := map[string]string{"app": "testapp"}
	pod1Annots := map[string]string{
		networksAnnot:      "net1,net2",
		networkStatusAnnot: `[{"name":"net1"},{"name":"net2","mac":"00:00:00:00:00:01"}]`,
	}
	pod1 := testPod("default", "pod1-delete", pod1Labels, pod1Annots)

	podNoMultiNetAnnots := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-no-multinet-delete", Namespace: "default"},
	}

	tests := []struct {
		name            string
		podToDelete     *v1.Pod
		setupCache      func()
		expectReconcile bool
	}{
		{
			name:        "Delete existing pod with multinetwork",
			podToDelete: pod1,
			setupCache: func() {
				cache.InitializePodCache()
				cache.AddPodToCache(pod1)
			},
			expectReconcile: true,
		},
		{
			name:        "Delete pod not in cache (but is multinetwork)",
			podToDelete: pod1,
			setupCache: func() {
				cache.InitializePodCache()
			},
			expectReconcile: true,
		},
		{
			name:        "Delete pod without multinetwork setup",
			podToDelete: podNoMultiNetAnnots,
			setupCache: func() {
				cache.InitializePodCache()
			},
			expectReconcile: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupCache()
			initialExists := cache.PodExistsInCache(tt.podToDelete.Namespace, tt.podToDelete.Name)

			reconcileNeeded := DeletePod(tt.podToDelete)
			assert.Equal(t, tt.expectReconcile, reconcileNeeded)

			if initialExists && tt.expectReconcile {
				assert.False(t, cache.PodExistsInCache(tt.podToDelete.Namespace, tt.podToDelete.Name), "Pod should be removed from cache")
			} else if initialExists && !tt.expectReconcile {
				assert.True(t, cache.PodExistsInCache(tt.podToDelete.Namespace, tt.podToDelete.Name), "Pod should still be in cache if not processed by delete handler")
			}
		})
	}
}
