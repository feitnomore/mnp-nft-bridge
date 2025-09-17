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
	"bytes"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func DecodeTableFamily(family nftables.TableFamily) string {
	switch family {
	case nftables.TableFamilyBridge:
		return "TableFamilyBridge"
	case nftables.TableFamilyARP:
		return "TableFamilyARP"
	case nftables.TableFamilyIPv4:
		return "TableFamilyIPv4"
	case nftables.TableFamilyIPv6:
		return "TableFamilyIPv6"
	case nftables.TableFamilyINet:
		return "TableFamilyINet"
	}
	return ""
}

func DecodeVerdict(input expr.VerdictKind) string {
	switch input {
	case expr.VerdictAccept:
		return "VerdictAccept"
	case expr.VerdictBreak:
		return "VerdictBreak"
	case expr.VerdictDrop:
		return "VerdictDrop"
	case expr.VerdictQueue:
		return "VerdictQueue"
	case expr.VerdictReturn:
		return "VerdictReturn"
	case expr.VerdictJump:
		return "VerdictJump"
	}
	return ""
}

func DecodeType(input nftables.ChainType) string {
	switch input {
	case nftables.ChainTypeFilter:
		return "filter"
	case nftables.ChainTypeNAT:
		return "nat"
	case nftables.ChainTypeRoute:
		return "route"
	}

	return ""
}

func DecodeExpr(input expr.Any) string {
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "%T", input)

	return buffer.String()
}

func DecodeByte(input []byte) string {
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "%s", string(input))

	return buffer.String()
}

func DecodeOp(input expr.CmpOp) string {
	switch input {
	case expr.CmpOpEq:
		return "CmpOpEq"
	case expr.CmpOpGt:
		return "CmpOpGt"
	case expr.CmpOpGte:
		return "CmpOpGte"
	case expr.CmpOpLt:
		return "CmpOpLt"
	case expr.CmpOpLte:
		return "CmpOpLte"
	case expr.CmpOpNeq:
		return "CmpOpNeq"
	}
	return ""
}
