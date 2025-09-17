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

import "strings"

/* ensures that the network name is in the format namespace/name. */
func NormalizeNetworkName(inputName, defaultNamespace string) string {
	if strings.Contains(inputName, "/") {
		return inputName /* It is already in namespace/name format */
	}
	if defaultNamespace == "" { /* If defaultNamespace is also empty, just return the name */
		return inputName
	}
	return defaultNamespace + "/" + inputName /* adds default namespace */
}

/* extract namespace and name from a string in the format "namespace/name" or "name". */
func ParseNamespacedName(inputName, defaultNamespace string) (string, string) {
	parts := strings.SplitN(inputName, "/", 2)
	if len(parts) == 2 {
		if parts[0] == "" { /* Case "/netname" - assume defaultNamespace */
			return defaultNamespace, parts[1]
		}
		return parts[0], parts[1]
	}
	return defaultNamespace, inputName
}
