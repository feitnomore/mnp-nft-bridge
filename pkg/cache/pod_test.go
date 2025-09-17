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
	"reflect"
	"testing"

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1" // Import para netdefv1.NetworkStatusAnnot
	"github.com/stretchr/testify/assert"                                                                        // Adicionado para TestGetPodsByLabels e outros
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPodCache(t *testing.T) {
	InitializePodCache()
	defer InitializePodCache() /* Limpa o cache após o teste */

	/* Test case 1: Add Pod to cache (com anotação de status válida para testar getMacFromStatusForCache) */
	pod1 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "namespace1",
			Labels: map[string]string{
				"app": "nginx",
			},
			Annotations: map[string]string{
				netdefv1.NetworkStatusAnnot: `[{"name":"net1","mac":"00:11:22:33:44:55"}]`,
			},
		},
		Spec: v1.PodSpec{},
	}
	AddPodToCache(pod1) /* Calls getMacFromStatusForCache internally  */
	expectedPod1 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "namespace1",
			Labels: map[string]string{
				"app": "nginx",
			},
			Annotations: map[string]string{
				netdefv1.NetworkStatusAnnot: `[{"name":"net1","mac":"00:11:22:33:44:55"}]`,
			},
		},
		Spec: v1.PodSpec{},
	}
	if !reflect.DeepEqual(podCache.Pods["namespace1/pod1"], expectedPod1) {
		t.Errorf("Pod1 not added correctly to cache")
	}

	/* Test case 2: Add another Pod to cache (sem anotações para testar outro caminho de getMacFromStatusForCache) */
	pod2 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod2",
			Namespace: "namespace2",
			Labels: map[string]string{
				"app": "myapp",
			},
		},
		Spec: v1.PodSpec{},
	}
	AddPodToCache(pod2) /* Calls getMacFromStatusForCache internally */
	expectedPod2 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod2",
			Namespace: "namespace2",
			Labels: map[string]string{
				"app": "myapp",
			},
		},
		Spec: v1.PodSpec{},
	}
	if !reflect.DeepEqual(podCache.Pods["namespace2/pod2"], expectedPod2) {
		t.Errorf("Pod2 not added correctly to cache")
	}

	/* Test case 3: Pod with Annotations but without NetworkStatusAnnot (for getMacFromStatusForCache) */
	pod3NoNetStatus := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod3-no-net-status",
			Namespace: "default",
			Annotations: map[string]string{
				"some-other-annotation": "value",
			},
		},
	}
	AddPodToCache(pod3NoNetStatus)

	/* Test case 4: Pod with empty NetworkStatusAnnot (for getMacFromStatusForCache) */
	pod4EmptyNetStatus := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod4-empty-net-status",
			Namespace: "default",
			Annotations: map[string]string{
				netdefv1.NetworkStatusAnnot: "",
			},
		},
	}
	AddPodToCache(pod4EmptyNetStatus)

	/* Test case 5: Get all Pods from cache */
	podList := GetPodsCache()
	if len(podList.Items) != 4 { // Ajustado para 4
		t.Errorf("Incorrect number of pods returned from cache, expected 4, got %d", len(podList.Items))
	}

	/* Test case 6: Get namespaced Pods from cache */
	namespacedPodList := GetNamespacedPodsCache("namespace1")
	if len(namespacedPodList.Items) != 1 {
		t.Errorf("Incorrect number of pods returned from namespaced cache, expected 1, got %d", len(namespacedPodList.Items))
	}

	/* Test case 7: Get specific Pod from cache */
	fetchedPod := GetPodFromCache("namespace1", "pod1")
	if !reflect.DeepEqual(fetchedPod, expectedPod1) {
		t.Errorf("Incorrect pod returned from cache")
	}

	/* Test case 8: Delete Pod from cache */
	DeletePodFromCache("namespace1", "pod1")
	if _, ok := podCache.Pods["namespace1/pod1"]; ok {
		t.Errorf("Pod1 not deleted from cache")
	}
	if len(podCache.Pods) != 3 { // Ajustado para 3
		t.Errorf("Incorrect number of pods in cache after deletion, expected 3, got %d", len(podCache.Pods))
	}

	/* Test case 9: Get full Pod cache */
	fullCache := GetFullPodCache()
	if len(fullCache.Pods) != 3 { // Ajustado para 3
		t.Errorf("Incorrect number of pods in full cache, expected 3, got %d", len(fullCache.Pods))
	}

	/* Test case 10: Check Pod exists in Cache */
	existsPod2 := PodExistsInCache("namespace2", "pod2")
	if !existsPod2 {
		t.Errorf("Expected to find pod namespace2/pod2 in cache, but it was not found")
	}

	/* Test case 11: Check Pod exists in Cache */
	existsPodNonExistent := PodExistsInCache("namespace3", "pod3-non-existent") // Nome diferente para clareza
	if existsPodNonExistent {
		t.Errorf("Did not expect to find pod namespace3/pod3-non-existent in cache, but it was found")
	}
}

func TestGetPodsByLabels(t *testing.T) {
	InitializePodCache()
	defer InitializePodCache()

	pod1 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-1",
			Namespace: "default",
			Labels: map[string]string{
				"app": "myapp",
				"env": "dev",
			},
		},
	}
	pod2 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-2",
			Namespace: "default",
			Labels: map[string]string{
				"app": "myapp",
				"env": "prod",
			},
		},
	}
	pod3 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-3",
			Namespace: "default",
			Labels: map[string]string{
				"app": "otherapp",
				"env": "dev",
			},
		},
	}
	AddPodToCache(pod1)
	AddPodToCache(pod2)
	AddPodToCache(pod3)

	testCases := []struct {
		name          string
		labels        map[string]string
		expectedPods  int
		expectedError bool
	}{
		{
			name:          "Match app=myapp",
			labels:        map[string]string{"app": "myapp"},
			expectedPods:  2,
			expectedError: false,
		},
		{
			name:          "Match app=myapp, env=prod",
			labels:        map[string]string{"app": "myapp", "env": "prod"},
			expectedPods:  1,
			expectedError: false,
		},
		{
			name:          "No match",
			labels:        map[string]string{"app": "no-such-app"},
			expectedPods:  0,
			expectedError: false,
		},
		{
			name:          "Empty labels",
			labels:        map[string]string{},
			expectedPods:  3,
			expectedError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pods, err := GetPodsByLabels(tc.labels)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if pods != nil {
					assert.Len(t, pods.Items, tc.expectedPods)
				} else if tc.expectedPods > 0 {
					t.Errorf("Expected %d pods, but got nil list", tc.expectedPods)
				}
			}
		})
	}
}

func TestPodMatchesLabels(t *testing.T) {
	podWithLabels := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod-with-labels",
			Labels: map[string]string{
				"app": "myapp",
				"env": "dev",
			},
		},
	}
	podWithNilLabels := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "pod-nil-labels",
			Labels: nil,
		},
	}

	testCases := []struct {
		name        string
		pod         *v1.Pod
		labels      map[string]string
		expected    bool
		expectPanic bool
	}{
		{
			name:     "Exact match",
			pod:      podWithLabels,
			labels:   map[string]string{"app": "myapp", "env": "dev"},
			expected: true,
		},
		{
			name:     "Partial match",
			pod:      podWithLabels,
			labels:   map[string]string{"app": "myapp"},
			expected: true,
		},
		{
			name:     "No match",
			pod:      podWithLabels,
			labels:   map[string]string{"app": "otherapp"},
			expected: false,
		},
		{
			name:     "Empty labels selector",
			pod:      podWithLabels,
			labels:   map[string]string{},
			expected: true,
		},
		{
			name:     "Pod with Nil labels, non-empty selector",
			pod:      podWithNilLabels,
			labels:   map[string]string{"app": "myapp"},
			expected: false,
		},
		{
			name:     "Pod with Nil labels, empty selector",
			pod:      podWithNilLabels,
			labels:   map[string]string{},
			expected: true,
		},
		{
			name:        "Nil Pod object causes panic",
			pod:         nil,
			labels:      map[string]string{"app": "myapp"},
			expected:    false,
			expectPanic: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.expectPanic {
				assert.Panics(t, func() {
					matchesPodLabels(tc.pod, tc.labels)
				}, "Expected matchesPodLabels to panic with nil pod")
			} else {
				if tc.pod == nil {
					t.Fatalf("Test case '%s' has a nil pod object unexpectedly and expectPanic is false", tc.name)
				}
				result := matchesPodLabels(tc.pod, tc.labels)
				if result != tc.expected {
					t.Errorf("Unexpected result for pod '%s' with labels %v: got %t, want %t", tc.pod.Name, tc.labels, result, tc.expected)
				}
			}
		})
	}
}

func TestGetNamespacedPodsByLabels(t *testing.T) {
	InitializePodCache()
	defer InitializePodCache()

	pod1 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "namespace1",
			Labels: map[string]string{
				"app": "nginx",
			},
		},
	}
	pod2 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod2",
			Namespace: "namespace1",
			Labels: map[string]string{
				"app": "myapp",
			},
		},
	}
	pod3 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod3",
			Namespace: "namespace2",
			Labels: map[string]string{
				"app": "myapp",
			},
		},
	}

	AddPodToCache(pod1)
	AddPodToCache(pod2)
	AddPodToCache(pod3)

	testCases := []struct {
		name          string
		namespace     string
		labels        map[string]string
		expectedPods  int
		expectedError bool
	}{
		{
			name:          "Match in namespace1, app=nginx",
			namespace:     "namespace1",
			labels:        map[string]string{"app": "nginx"},
			expectedPods:  1,
			expectedError: false,
		},
		{
			name:          "Match in namespace1, app=myapp",
			namespace:     "namespace1",
			labels:        map[string]string{"app": "myapp"},
			expectedPods:  1,
			expectedError: false,
		},
		{
			name:          "Match in namespace2, app=myapp",
			namespace:     "namespace2",
			labels:        map[string]string{"app": "myapp"},
			expectedPods:  1,
			expectedError: false,
		},
		{
			name:          "No match in namespace1",
			namespace:     "namespace1",
			labels:        map[string]string{"app": "no-such-app"},
			expectedPods:  0,
			expectedError: false,
		},
		{
			name:          "No match in namespace3 (non-existent namespace in cache for this test)",
			namespace:     "namespace3",
			labels:        map[string]string{"app": "myapp"},
			expectedPods:  0,
			expectedError: false,
		},
		{
			name:          "Empty labels, namespace1",
			namespace:     "namespace1",
			labels:        map[string]string{},
			expectedPods:  2,
			expectedError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pods, err := GetNamespacedPodsByLabels(tc.namespace, tc.labels)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if pods != nil {
					assert.Len(t, pods.Items, tc.expectedPods)
				} else if tc.expectedPods > 0 {
					t.Errorf("Expected %d pods, but got nil list", tc.expectedPods)
				}
			}
		})
	}
}

func TestGetNamespacedPods(t *testing.T) {
	InitializePodCache()
	defer InitializePodCache()

	pod1 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "namespace1",
			Labels: map[string]string{
				"app": "nginx",
			},
		},
	}
	pod2 := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod2",
			Namespace: "namespace1",
			Labels: map[string]string{
				"app": "myapp",
			},
		},
	}
	pod3InNs2 := &v1.Pod{ /* Add a pod in another namespace to test filtering */
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod3",
			Namespace: "namespace2",
		},
	}

	AddPodToCache(pod1)
	AddPodToCache(pod2)
	AddPodToCache(pod3InNs2)

	testCases := []struct {
		name          string
		namespace     string
		expectedPods  int
		expectedError bool
	}{
		{
			name:          "Match in namespace1",
			namespace:     "namespace1",
			expectedPods:  2,
			expectedError: false,
		},
		{
			name:          "Match in namespace2",
			namespace:     "namespace2",
			expectedPods:  1,
			expectedError: false,
		},
		{
			name:          "No match in namespace3 (non-existent namespace in cache for this test)",
			namespace:     "namespace3",
			expectedPods:  0,
			expectedError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pods, err := GetNamespacedPods(tc.namespace)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if pods != nil {
					assert.Len(t, pods.Items, tc.expectedPods)
				} else if tc.expectedPods > 0 {
					t.Errorf("Expected %d pods, but got nil list", tc.expectedPods)
				}
			}
		})
	}
}
