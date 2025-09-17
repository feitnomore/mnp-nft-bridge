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
	"testing"
)

func TestNftablesCache(t *testing.T) {
	InitializeNftablesCache()

	/* Test case 1: Add Ingress Rule ID */
	AddIngressRuleID("rule1", "chain1")
	if !CheckIngressRuleID("rule1") {
		t.Error("Ingress rule ID not found in cache after adding")
	}

	/* Test case 2: Add another Ingress Rule ID */
	AddIngressRuleID("rule2", "chain2")
	if !CheckIngressRuleID("rule2") {
		t.Error("Ingress rule ID not found in cache after adding")
	}

	/* Test case 3: Get all Ingress Rule IDs */
	ruleIDs := GetIngressRuleIDs()
	if len(ruleIDs) != 2 {
		t.Errorf("Incorrect number of ingress rule IDs returned, expected 2, got %d", len(ruleIDs))
	}

	/* Test case 4: Delete Ingress Rule ID */
	DeleteIngressRuleID("rule1")
	if CheckIngressRuleID("rule1") {
		t.Error("Ingress rule ID still found in cache after deleting")
	}
	if len(nftCache.IngressRules) != 1 {
		t.Errorf("Incorrect number of ingress rule IDs in cache after deletion, expected 1, got %d", len(nftCache.IngressRules))
	}

	/* Test case 5: Add Egress Rule ID */
	AddEgressRuleID("rule3", "chain3")
	if !CheckEgressRuleID("rule3") {
		t.Error("Egress rule ID not found in cache after adding")
	}

	/* Test case 6: Add another Egress Rule ID */
	AddEgressRuleID("rule4", "chain4")
	if !CheckEgressRuleID("rule4") {
		t.Error("Egress rule ID not found in cache after adding")
	}

	/* Test case 7: Get all Egress Rule IDs */
	ruleIDs = GetEgressRuleIDs()
	if len(ruleIDs) != 2 {
		t.Errorf("Incorrect number of egress rule IDs returned, expected 2, got %d", len(ruleIDs))
	}

	/* Test case 8: Delete Egress Rule ID */
	DeleteEgressRuleID("rule3")
	if CheckEgressRuleID("rule3") {
		t.Error("Egress rule ID still found in cache after deleting")
	}
	if len(nftCache.EgressRules) != 1 {
		t.Errorf("Incorrect number of egress rule IDs in cache after deletion, expected 1, got %d", len(nftCache.EgressRules))
	}
}
