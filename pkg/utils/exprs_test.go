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

	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
)

func TestNormalizeExprsForComparison(t *testing.T) {
	tests := []struct {
		name        string
		expressions []expr.Any
		expected    string
	}{
		{
			name:        "Empty expressions",
			expressions: []expr.Any{},
			expected:    "[]",
		},
		{
			name: "Single expression without Handle or SetID",
			expressions: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			},
			expected: `[{"Key":6,"SourceRegister":false,"Register":1}]`,
		},
		{
			name: "Single expression Counter",
			expressions: []expr.Any{
				&expr.Counter{Bytes: 100, Packets: 10},
			},
			expected: `[{"Bytes":100,"Packets":10}]`,
		},
		{
			name: "Single expression with SetID",
			expressions: []expr.Any{
				&expr.Lookup{SourceRegister: 1, SetName: "myset", SetID: 54321},
			},
			expected: `[{"SourceRegister":1,"DestRegister":0,"IsDestRegSet":false,"SetName":"myset","Invert":false}]`,
		},
		{
			name: "Multiple expressions with SetID",
			expressions: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Counter{Bytes: 100, Packets: 10},
				&expr.Lookup{SourceRegister: 1, SetName: "testset", SetID: 789},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			expected: `[{"Key":6,"SourceRegister":false,"Register":1},{"Bytes":100,"Packets":10},{"SourceRegister":1,"DestRegister":0,"IsDestRegSet":false,"SetName":"testset","Invert":false},{"Kind":1,"Chain":""}]`,
		},
		{
			name: "Expressions with nested structures (e.g., Cmp with Data)",
			expressions: []expr.Any{
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x08, 0x00}},
			},
			expected: `[{"Op":0,"Register":1,"Data":"CAA="}]`,
		},
		{
			name:        "Nil expressions slice",
			expressions: nil,
			expected:    "null",
		},
		{
			name: "Expression Counter then Meta",
			expressions: []expr.Any{
				&expr.Counter{Bytes: 100, Packets: 10},
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			},
			expected: `[{"Bytes":100,"Packets":10},{"Key":6,"SourceRegister":false,"Register":1}]`,
		},
		{
			name: "Expression Lookup then Meta",
			expressions: []expr.Any{
				&expr.Lookup{SourceRegister: 1, SetName: "testset", SetID: 789},
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			},
			expected: `[{"SourceRegister":1,"DestRegister":0,"IsDestRegSet":false,"SetName":"testset","Invert":false},{"Key":6,"SourceRegister":false,"Register":1}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := NormalizeExprsForComparison(tt.expressions)
			assert.Equal(t, tt.expected, normalized)
		})
	}
}
