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
	"testing"

	"github.com/feitnomore/mnp-nft-bridge/pkg/cache" // Importa o pacote cache
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/* Helper for creating a test namespace */
func testNamespace(name string, labels map[string]string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Spec: v1.NamespaceSpec{}, /* Spec can be empty for these tests */
	}
}

func TestAddNamespaceHandler(t *testing.T) {
	tests := []struct {
		name            string
		namespaceToAdd  *v1.Namespace
		initialCache    map[string]*v1.Namespace /* Initial cache state */
		expectReconcile bool
		expectInCache   bool
	}{
		{
			name:            "Add new namespace",
			namespaceToAdd:  testNamespace("ns1", map[string]string{"env": "test"}),
			initialCache:    map[string]*v1.Namespace{},
			expectReconcile: true,
			expectInCache:   true,
		},
		{
			name:           "Add namespace that already exists",
			namespaceToAdd: testNamespace("ns1", map[string]string{"env": "test"}),
			initialCache: map[string]*v1.Namespace{
				"ns1": testNamespace("ns1", map[string]string{"env": "test"}),
			},
			expectReconcile: false, /* Should not reconcile if there is no actual change (AddNamespace checks for existence) */
			expectInCache:   true,  /* Must remain in cache */
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.InitializeNamespaceCache() /* Clear and initialize the cache */
			for k, v := range tt.initialCache {
				/* Adds directly to cache to simulate pre-existing state */
				cache.AddNamespaceCache(v)
				/* Check if the key is correct (namespace name) */
				if k != v.Name {
					t.Fatalf("Initial cache key '%s' does not match namespace name '%s'", k, v.Name)
				}
			}

			reconcile := AddNamespace(tt.namespaceToAdd)
			assert.Equal(t, tt.expectReconcile, reconcile)

			if tt.expectInCache {
				cachedNs := cache.GetNamespaceFromCache(tt.namespaceToAdd.Name)
				require.NotNil(t, cachedNs)
				assert.Equal(t, tt.namespaceToAdd.Name, cachedNs.Name)
				assert.Equal(t, tt.namespaceToAdd.Labels, cachedNs.Labels)
			} else {
				/* If we don't expect it to be in the cache (or it hasn't been added), we check for its absence.
				 * In the case of "already exists," it will be there, but reconcile will be false.
				 */
				if !tt.expectReconcile && len(tt.initialCache) > 0 && tt.initialCache[tt.namespaceToAdd.Name] != nil {
					/* Already existed, must not have been modified if AddNamespace returns false */
					cachedNs := cache.GetNamespaceFromCache(tt.namespaceToAdd.Name)
					require.NotNil(t, cachedNs) // Deve existir
				} else {
					assert.Nil(t, cache.GetNamespaceFromCache(tt.namespaceToAdd.Name))
				}
			}
		})
	}
}

func TestUpdateNamespaceHandler(t *testing.T) {
	baseLabels := map[string]string{"env": "test", "team": "alpha"}
	updatedLabels := map[string]string{"env": "prod", "team": "alpha"}

	tests := []struct {
		name              string
		namespaceInCache  *v1.Namespace /* NS state in cache before Update */
		namespaceToUpdate *v1.Namespace /* "New" NS coming from event */
		expectReconcile   bool
		expectLabels      map[string]string /* Labels expected in cache after update */
	}{
		{
			name:              "Update existing namespace with label change",
			namespaceInCache:  testNamespace("ns-update", baseLabels),
			namespaceToUpdate: testNamespace("ns-update", updatedLabels),
			expectReconcile:   true,
			expectLabels:      updatedLabels,
		},
		{
			name:              "Update existing namespace with no label change",
			namespaceInCache:  testNamespace("ns-nochange", baseLabels),
			namespaceToUpdate: testNamespace("ns-nochange", baseLabels), /* Same labels */
			expectReconcile:   false,
			expectLabels:      baseLabels,
		},
		{
			name:              "Update namespace not in cache (behaves like add)",
			namespaceInCache:  nil, /* Not in cache */
			namespaceToUpdate: testNamespace("ns-new-on-update", updatedLabels),
			expectReconcile:   true,
			expectLabels:      updatedLabels,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.InitializeNamespaceCache()
			if tt.namespaceInCache != nil {
				cache.AddNamespaceCache(tt.namespaceInCache)
			}

			reconcile := UpdateNamespace(tt.namespaceToUpdate)
			assert.Equal(t, tt.expectReconcile, reconcile)

			cachedNs := cache.GetNamespaceFromCache(tt.namespaceToUpdate.Name)
			require.NotNil(t, cachedNs, "Namespace should be cached after Add/Update")
			assert.Equal(t, tt.expectLabels, cachedNs.Labels)
		})
	}
}

func TestDeleteNamespaceHandler(t *testing.T) {
	tests := []struct {
		name              string
		namespaceToDelete *v1.Namespace
		initialCache      map[string]*v1.Namespace
		expectReconcile   bool
		expectNotInCache  bool
	}{
		{
			name:              "Delete existing namespace",
			namespaceToDelete: testNamespace("ns-to-delete", nil),
			initialCache: map[string]*v1.Namespace{
				"ns-to-delete": testNamespace("ns-to-delete", nil),
			},
			expectReconcile:  true,
			expectNotInCache: true,
		},
		{
			name:              "Delete namespace not in cache",
			namespaceToDelete: testNamespace("ns-not-there", nil),
			initialCache:      map[string]*v1.Namespace{},
			expectReconcile:   true, /* DeleteNamespace always returns true */
			expectNotInCache:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.InitializeNamespaceCache()
			for _, ns := range tt.initialCache {
				cache.AddNamespaceCache(ns)
			}

			reconcile := DeleteNamespace(tt.namespaceToDelete)
			assert.Equal(t, tt.expectReconcile, reconcile)

			if tt.expectNotInCache {
				assert.False(t, cache.NamespaceExistsInCache(tt.namespaceToDelete.Name))
			}
		})
	}
}
