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

import "testing"

func TestNftCheckChain(t *testing.T) {
	testCases := []struct {
		name      string
		chainName string
		expected  bool
	}{
		{"Ingress Chain Valid", "KUBE_MULTI_INGRESS_abc", true},
		{"Egress Chain Valid", "KUBE_MULTI_EGRESS_def", true},
		{"Ingress Chain Invalid Prefix", "KUBE_INGRESS_abc", false},
		{"No Prefix", "MY_CHAIN", false},
		{"Empty Chain", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := CheckChain(tc.chainName)
			if actual != tc.expected {
				t.Errorf("CheckChain(%s): expected %v, got %v", tc.chainName, tc.expected, actual)
			}
		})
	}
}
