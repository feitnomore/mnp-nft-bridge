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
	"encoding/hex"
	"regexp"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
)

func TestGenerateHash(t *testing.T) {
	input1 := "testString1"
	hash1A := GenerateHash(input1)
	hash1B := GenerateHash(input1)

	assert.Equal(t, hash1A, hash1B, "GenerateHash should be deterministic for the same input")
	assert.Len(t, hash1A, TruncatedHashBytes*2, "Generated hash should be twice the length of TruncatedHashBytes (hex encoding)")

	input2 := "anotherTestString"
	hash2 := GenerateHash(input2)
	assert.NotEqual(t, hash1A, hash2, "GenerateHash should produce different hashes for different inputs")

	_, err := hex.DecodeString(hash1A)
	assert.NoError(t, err, "Generated hash should be a valid hex string")
}

func TestGenerateRandUInt32(t *testing.T) {
	val1 := GenerateRandUInt32()
	val2 := GenerateRandUInt32()
	val3 := GenerateRandUInt32()

	assert.NotEqual(t, val1, val2, "Two consecutive random uint32s are unlikely to be equal (probabilistic)")
	t.Logf("Generated random uint32s: %d, %d, %d", val1, val2, val3)
}

func TestGenerateRandomShortID(t *testing.T) {
	id1 := GenerateRandomShortID()
	id2 := GenerateRandomShortID()

	assert.Len(t, id1, 6, "Generated short ID should have length 6")

	match, _ := regexp.MatchString(`^\d{6}$`, id1)
	assert.True(t, match, "Generated short ID '%s' should be 6 digits", id1)

	assert.NotEqual(t, id1, id2, "Two consecutive random short IDs are unlikely to be equal (probabilistic)")
	t.Logf("Generated random short IDs: %s, %s", id1, id2)
}

func TestGenerateRuleID(t *testing.T) {
	rule1Exprs := []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}}
	rule1 := &nftables.Rule{Exprs: rule1Exprs}
	id1a := GenerateRuleID(rule1)
	id1b := GenerateRuleID(rule1)

	rule2Exprs := []expr.Any{&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}}
	rule2 := &nftables.Rule{Exprs: rule2Exprs}
	id2 := GenerateRuleID(rule2)

	assert.NotEmpty(t, id1a, "Rule ID should not be empty")
	assert.Equal(t, id1a, id1b, "GenerateRuleID should be deterministic for the same rule expressions")
	assert.NotEqual(t, id1a, id2, "GenerateRuleID should produce different IDs for different rule expressions")
	assert.Len(t, id1a, 64, "Rule ID should be a full SHA256 hex string (64 chars)")
}

func TestGenerateDeterministicSetID(t *testing.T) {
	id1A := GenerateDeterministicSetID("suffixA", "ingress", 0, "src-ip")
	id1B := GenerateDeterministicSetID("suffixA", "ingress", 0, "src-ip")
	assert.Equal(t, id1A, id1B, "Expected same ID for same inputs")

	id2 := GenerateDeterministicSetID("suffixB", "ingress", 0, "src-ip")
	assert.NotEqual(t, id1A, id2, "Expected different ID for different chainSuffix")

	id3 := GenerateDeterministicSetID("suffixA", "egress", 0, "src-ip")
	assert.NotEqual(t, id1A, id3, "Expected different ID for different ruleDirection")

	id4 := GenerateDeterministicSetID("suffixA", "ingress", 1, "src-ip")
	assert.NotEqual(t, id1A, id4, "Expected different ID for different ruleIndex")

	id5 := GenerateDeterministicSetID("suffixA", "ingress", 0, "dst-mac")
	assert.NotEqual(t, id1A, id5, "Expected different ID for different setType")

	assert.Len(t, id1A, 64, "DeterministicSetID should be a full SHA256 hex string (64 chars)")
}

func TestParseUint32FromHex(t *testing.T) {
	tests := []struct {
		name     string
		hexStr   string
		expected uint32
	}{
		{"Empty string", "", 0},
		{"0x prefix only", "0x", 0},
		{"Valid short hex", "0xA", 10},
		{"Valid short hex no prefix", "A", 10},
		{"Valid full hex", "0xFFFFFFFF", 0xFFFFFFFF},
		{"Valid full hex no prefix", "FFFFFFFF", 0xFFFFFFFF},
		{"Hex longer than 8 chars (prefix)", "0x123456789ABC", 0x12345678},      /* Truncates to first 8 after 0x */
		{"Hex longer than 8 chars (no prefix)", "123456789ABCDEF0", 0x12345678}, /* Truncates to first 8 */
		{"Odd length hex", "0xABC", 0x0ABC},
		{"Odd length hex no prefix", "ABC", 0x0ABC},
		{"Invalid hex characters with prefix", "0xGHI", 0},
		{"Invalid hex characters no prefix", "GHI", 0},
		{"Zero value with prefix", "0x0", 0},
		{"Zero value no prefix", "0", 0},
		{"Max uint32", "ffffffff", 4294967295},
		{"Slightly less than max", "fffffffe", 4294967294},
		{"Hex string becomes empty after trim prefix", "0x", 0}, /* Already covered by "0x prefix only" */
		{"Hex string with only prefix and odd valid char", "0xF", 15},
		{"Hex string with only prefix and even valid chars", "0xAB", 0xAB},
		{"Hex string very long, odd length after prefix", "0x123456789", 0x12345678},   /* Already covered */
		{"Hex string very long, even length after prefix", "0x123456789A", 0x12345678}, /* Already covered */
		{"Hex string that would be empty after trim and padding logic (edge case, GHI becomes 0GHI, fails decode)", "G", 0}, /* hex.DecodeString("0G") */
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseUint32FromHex(tt.hexStr))
		})
	}
}
