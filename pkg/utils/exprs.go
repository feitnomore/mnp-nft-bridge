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
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/google/nftables/expr"
	"k8s.io/klog/v2"
)

/* normalizeExprsForComparison serializes expressions to a canonical string for comparison. */
func NormalizeExprsForComparison(expressions []expr.Any) string {
	reHandle := regexp.MustCompile(`"Handle":\s*\d+,?`)
	reSetID := regexp.MustCompile(`"SetID":\s*\d+,?`)

	rawJSON, err := json.Marshal(expressions)
	if err != nil {
		klog.Warningf("normalizeExprsForComparison: Failed to marshal expressions: %v. Comparison will likely fail.", err)
		return fmt.Sprintf("error-marshalling-%v", expressions)
	}

	normalizedJSONStr := string(rawJSON)
	normalizedJSONStr = reHandle.ReplaceAllString(normalizedJSONStr, "")
	normalizedJSONStr = reSetID.ReplaceAllString(normalizedJSONStr, "")
	normalizedJSONStr = regexp.MustCompile(`,{2,}`).ReplaceAllString(normalizedJSONStr, ",")
	normalizedJSONStr = regexp.MustCompile(`,\s*}`).ReplaceAllString(normalizedJSONStr, "}")
	normalizedJSONStr = regexp.MustCompile(`,\s*]`).ReplaceAllString(normalizedJSONStr, "]")

	return normalizedJSONStr
}
