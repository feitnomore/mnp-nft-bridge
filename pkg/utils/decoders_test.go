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
	"fmt"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func TestDecodeTableFamily(t *testing.T) {
	testCases := []struct {
		input    nftables.TableFamily
		expected string
	}{
		{nftables.TableFamilyBridge, "TableFamilyBridge"},
		{nftables.TableFamilyARP, "TableFamilyARP"},
		{nftables.TableFamilyIPv4, "TableFamilyIPv4"},
		{nftables.TableFamilyIPv6, "TableFamilyIPv6"},
		{nftables.TableFamilyINet, "TableFamilyINet"},
		{nftables.TableFamily(100), ""},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Input_Family_%v", tc.input), func(t *testing.T) {
			actual := DecodeTableFamily(tc.input)
			if actual != tc.expected {
				t.Errorf("Expected: %s, Got: %s", tc.expected, actual)
			}
		})
	}
}

func TestDecodeVerdict(t *testing.T) {
	testCases := []struct {
		input    expr.VerdictKind
		expected string
	}{
		{expr.VerdictAccept, "VerdictAccept"},
		{expr.VerdictBreak, "VerdictBreak"},
		{expr.VerdictDrop, "VerdictDrop"},
		{expr.VerdictQueue, "VerdictQueue"},
		{expr.VerdictReturn, "VerdictReturn"},
		{expr.VerdictJump, "VerdictJump"},
		{expr.VerdictKind(100), ""},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Input_Verdict_%v", tc.input), func(t *testing.T) {
			actual := DecodeVerdict(tc.input)
			if actual != tc.expected {
				t.Errorf("Expected: %s, Got: %s", tc.expected, actual)
			}
		})
	}
}

func TestDecodeType(t *testing.T) {
	testCases := []struct {
		input    nftables.ChainType
		expected string
	}{
		{nftables.ChainTypeFilter, "filter"},
		{nftables.ChainTypeNAT, "nat"},
		{nftables.ChainTypeRoute, "route"},
		{nftables.ChainType("invalid_type"), ""},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Input_Type_%v", tc.input), func(t *testing.T) {
			actual := DecodeType(tc.input)
			if actual != tc.expected {
				t.Errorf("Expected: %s, Got: %s", tc.expected, actual)
			}
		})
	}
}

func TestDecodeExpr(t *testing.T) {
	testCases := []struct {
		name     string
		input    expr.Any
		expected string
	}{
		{"Payload", &expr.Payload{}, "*expr.Payload"},
		{"Meta", &expr.Meta{}, "*expr.Meta"},
		{"Cmp", &expr.Cmp{}, "*expr.Cmp"},
		{"Log", &expr.Log{}, "*expr.Log"},
		{"Match", &expr.Match{}, "*expr.Match"},
		{"Verdict", &expr.Verdict{}, "*expr.Verdict"},
		{"Counter", &expr.Counter{}, "*expr.Counter"},
		{"Lookup", &expr.Lookup{}, "*expr.Lookup"},
		{"Dynset", &expr.Dynset{}, "*expr.Dynset"},
		{"Immediate", &expr.Immediate{}, "*expr.Immediate"},
		{"Range", &expr.Range{}, "*expr.Range"},
		{"Bitwise", &expr.Bitwise{}, "*expr.Bitwise"},
		{"Ct", &expr.Ct{}, "*expr.Ct"},
		{"NAT", &expr.NAT{}, "*expr.NAT"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := DecodeExpr(tc.input)
			if actual != tc.expected {
				t.Errorf("Expected: %s, Got: %s", tc.expected, actual)
			}
		})
	}
}

func TestDecodeByte(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"Simple string", []byte("test"), "test"},
		{"Empty byte slice", []byte(""), ""},
		{"Nil byte slice", nil, ""},
		{"String with numbers", []byte("test123"), "test123"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := DecodeByte(tc.input)
			if actual != tc.expected {
				t.Errorf("Expected: %s, Got: %s", tc.expected, actual)
			}
		})
	}
}

func TestDecodeOp(t *testing.T) {
	testCases := []struct {
		input    expr.CmpOp
		expected string
	}{
		{expr.CmpOpEq, "CmpOpEq"},
		{expr.CmpOpGt, "CmpOpGt"},
		{expr.CmpOpGte, "CmpOpGte"},
		{expr.CmpOpLt, "CmpOpLt"},
		{expr.CmpOpLte, "CmpOpLte"},
		{expr.CmpOpNeq, "CmpOpNeq"},
		{expr.CmpOp(100), ""},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Input_Op_%v", tc.input), func(t *testing.T) {
			actual := DecodeOp(tc.input)
			if actual != tc.expected {
				t.Errorf("Expected: %s, Got: %s", tc.expected, actual)
			}
		})
	}
}
