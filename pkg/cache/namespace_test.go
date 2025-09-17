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

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNamespaceCache(t *testing.T) {
	InitializeNamespaceCache()

	/* Test case 1: Add Namespace to cache */
	namespace1 := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
			Labels: map[string]string{
				"label1": "value1",
			},
		},
		Spec: v1.NamespaceSpec{},
	}
	AddNamespaceCache(namespace1)
	expectedNamespace1 := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace1",
			Labels: map[string]string{
				"label1": "value1",
			},
		},
		Spec: v1.NamespaceSpec{},
	}
	if !reflect.DeepEqual(namespaceCache.Namespaces["namespace1"], expectedNamespace1) {
		t.Errorf("Namespace1 not added correctly to cache")
	}

	/* Test case 2: Add another Namespace to cache */
	namespace2 := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace2",
			Labels: map[string]string{
				"label2": "value2",
			},
		},
		Spec: v1.NamespaceSpec{},
	}
	AddNamespaceCache(namespace2)
	expectedNamespace2 := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "namespace2",
			Labels: map[string]string{
				"label2": "value2",
			},
		},
		Spec: v1.NamespaceSpec{},
	}
	if !reflect.DeepEqual(namespaceCache.Namespaces["namespace2"], expectedNamespace2) {
		t.Errorf("Namespace2 not added correctly to cache")
	}

	/* Test case 3: Get all Namespaces from cache */
	nsList := GetNamespaceCache()
	if len(nsList.Items) != 2 {
		t.Errorf("Incorrect number of namespaces returned from cache, expected 2, got %d", len(nsList.Items))
	}

	/* Test case 4: Get specific Namespace from cache */
	fetchedNamespace := GetNamespaceFromCache("namespace1")
	if !reflect.DeepEqual(fetchedNamespace, expectedNamespace1) {
		t.Errorf("Incorrect namespace returned from cache")
	}

	/* Test case 5: Delete Namespace from cache */
	DeleteNamespaceFromCache("namespace1")
	if _, ok := namespaceCache.Namespaces["namespace1"]; ok {
		t.Errorf("Namespace1 not deleted from cache")
	}
	if len(namespaceCache.Namespaces) != 1 {
		t.Errorf("Incorrect number of namespaces in cache after deletion, expected 1, got %d", len(namespaceCache.Namespaces))
	}

	/* Test case 6: Check Namespace exists in Cache */
	existsNamespace2 := NamespaceExistsInCache("namespace2")
	if !existsNamespace2 {
		t.Errorf("Expected to find Namespace namespace2 in cache, but it was not found")
	}

	/* Test case 7: Check Namespace exists in Cache */
	existsNamespace3 := NamespaceExistsInCache("namespace3")
	if existsNamespace3 {
		t.Errorf("Did not expect to find Namespace namespace3 in cache, but it was found")
	}
}

func TestNamespaceMatchesLabels(t *testing.T) {
	baseNs := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "base-ns",
			Labels: map[string]string{
				"app": "myapp",
				"env": "dev",
			},
		},
	}

	nilLabelsNs := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nil-labels-ns",
			Labels: nil,
		},
	}

	testCases := []struct {
		name        string
		ns          *v1.Namespace
		labels      map[string]string
		expected    bool
		expectPanic bool
	}{
		{
			name:        "Exact match",
			ns:          baseNs,
			labels:      map[string]string{"app": "myapp", "env": "dev"},
			expected:    true,
			expectPanic: false,
		},
		{
			name:        "Partial match",
			ns:          baseNs,
			labels:      map[string]string{"app": "myapp"},
			expected:    true,
			expectPanic: false,
		},
		{
			name:        "No match",
			ns:          baseNs,
			labels:      map[string]string{"app": "otherapp"},
			expected:    false,
			expectPanic: false,
		},
		{
			name:        "Empty labels selector",
			ns:          baseNs,
			labels:      map[string]string{},
			expected:    true,
			expectPanic: false,
		},
		{
			name:        "Namespace with Nil labels, non-empty selector",
			ns:          nilLabelsNs,
			labels:      map[string]string{"app": "myapp"},
			expected:    false,
			expectPanic: false,
		},
		{
			name:        "Namespace with Nil labels, empty selector",
			ns:          nilLabelsNs,
			labels:      map[string]string{},
			expected:    true,
			expectPanic: false,
		},
		{
			name:        "Nil Namespace object causes panic",
			ns:          nil,
			labels:      map[string]string{"app": "myapp"},
			expected:    false,
			expectPanic: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.expectPanic {
				assert.Panics(t, func() {
					matchesNamespaceLabels(tc.ns, tc.labels)
				}, "Expected matchesNamespaceLabels to panic with nil namespace")
			} else {
				if tc.ns == nil {
					t.Fatalf("Test case '%s' has a nil namespace object unexpectedly and expectPanic is false", tc.name)
				}
				result := matchesNamespaceLabels(tc.ns, tc.labels)
				if result != tc.expected {
					t.Errorf("Unexpected result for ns '%s' with labels %v: got %t, want %t", tc.ns.Name, tc.labels, result, tc.expected)
				}
			}
		})
	}
}

func TestGetNamespacesByLabels(t *testing.T) {
	InitializeNamespaceCache()
	defer func() {
		InitializeNamespaceCache()
	}()

	ns1 := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns-1",
			Labels: map[string]string{
				"app": "myapp",
				"env": "dev",
			},
		},
	}
	ns2 := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns-2",
			Labels: map[string]string{
				"app": "myapp",
				"env": "prod",
			},
		},
	}
	ns3 := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns-3",
			Labels: map[string]string{
				"app": "otherapp",
				"env": "dev",
			},
		},
	}
	AddNamespaceCache(ns1)
	AddNamespaceCache(ns2)
	AddNamespaceCache(ns3)

	testCases := []struct {
		name               string
		labels             map[string]string
		expectedNamespaces int
		expectedError      bool
	}{
		{
			name:               "Match app=myapp",
			labels:             map[string]string{"app": "myapp"},
			expectedNamespaces: 2,
			expectedError:      false,
		},
		{
			name:               "Match app=myapp, env=prod",
			labels:             map[string]string{"app": "myapp", "env": "prod"},
			expectedNamespaces: 1,
			expectedError:      false,
		},
		{
			name:               "No match",
			labels:             map[string]string{"app": "no-such-app"},
			expectedNamespaces: 0,
			expectedError:      false,
		},
		{
			name:               "Empty labels",
			labels:             map[string]string{},
			expectedNamespaces: 3,
			expectedError:      false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			namespaces, err := GetNamespacesByLabels(tc.labels)
			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error but got one")
				if namespaces != nil {
					assert.Len(t, namespaces.Items, tc.expectedNamespaces, "Unexpected number of namespaces")
				} else if tc.expectedNamespaces > 0 {
					t.Errorf("Expected %d namespaces, but got nil list", tc.expectedNamespaces)
				}
			}
		})
	}
}
