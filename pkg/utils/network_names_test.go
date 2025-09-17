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
package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeNetworkName(t *testing.T) {
	tests := []struct {
		name             string
		inputName        string
		defaultNamespace string
		expected         string
	}{
		{
			name:             "Already namespaced",
			inputName:        "kube-system/kindnet",
			defaultNamespace: "default",
			expected:         "kube-system/kindnet",
		},
		{
			name:             "Not namespaced, default ns provided",
			inputName:        "my-nad",
			defaultNamespace: "app-ns",
			expected:         "app-ns/my-nad",
		},
		{
			name:             "Not namespaced, default ns empty",
			inputName:        "my-nad-no-default",
			defaultNamespace: "",
			expected:         "my-nad-no-default",
		},
		{
			name:             "Input starts with slash, default ns provided",
			inputName:        "/my-nad-slash",
			defaultNamespace: "default",
			expected:         "/my-nad-slash",
		},
		{
			name:             "Input is empty, default ns provided",
			inputName:        "",
			defaultNamespace: "default",
			expected:         "default/", /* strings.Contains("", "/") is false */
		},
		{
			name:             "Input is empty, default ns empty",
			inputName:        "",
			defaultNamespace: "",
			expected:         "", /* strings.Contains("", "/") is false */
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, NormalizeNetworkName(tt.inputName, tt.defaultNamespace))
		})
	}
}

func TestParseNamespacedName(t *testing.T) {
	tests := []struct {
		name              string
		inputName         string
		defaultNamespace  string
		expectedNamespace string
		expectedName      string
	}{
		{
			name:              "Fully namespaced name",
			inputName:         "kube-system/kindnet",
			defaultNamespace:  "default",
			expectedNamespace: "kube-system",
			expectedName:      "kindnet",
		},
		{
			name:              "Only name, default ns provided",
			inputName:         "my-nad",
			defaultNamespace:  "app-ns",
			expectedNamespace: "app-ns",
			expectedName:      "my-nad",
		},
		{
			name:              "Only name, default ns empty",
			inputName:         "my-nad-no-default",
			defaultNamespace:  "",
			expectedNamespace: "",
			expectedName:      "my-nad-no-default",
		},
		{
			name:              "Starts with slash, default ns provided",
			inputName:         "/my-nad-slash",
			defaultNamespace:  "default",
			expectedNamespace: "default",
			expectedName:      "my-nad-slash",
		},
		{
			name:              "Starts with slash, no default ns (empty first part)",
			inputName:         "/my-nad-slash-no-default",
			defaultNamespace:  "",
			expectedNamespace: "",
			expectedName:      "my-nad-slash-no-default",
		},
		{
			name:              "Empty input name, default ns provided",
			inputName:         "",
			defaultNamespace:  "default",
			expectedNamespace: "default",
			expectedName:      "",
		},
		{
			name:              "Empty input name, empty default ns",
			inputName:         "",
			defaultNamespace:  "",
			expectedNamespace: "",
			expectedName:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, name := ParseNamespacedName(tt.inputName, tt.defaultNamespace)
			assert.Equal(t, tt.expectedNamespace, ns, "Namespace mismatch")
			assert.Equal(t, tt.expectedName, name, "Name mismatch")
		})
	}
}
