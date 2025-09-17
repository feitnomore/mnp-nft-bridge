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
package types

import (
	"net"
	"reflect"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

/* Helper to create an NFTables instance for testing, if necessary.
 * For nft_exprs, the functions are methods of *NFTables, but they don't use nft's internal state.
 * So, a simple nft := &NFTables{} should suffice.
 */
var testNft = &NFTables{}

func TestBuildExprCheckProtoIP(t *testing.T) {
	expectedExprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyPROTOCOL, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(unix.ETH_P_IP)},
	}
	actualExprs := testNft.buildExprCheckProtoIP()

	if !reflect.DeepEqual(actualExprs, expectedExprs) {
		t.Errorf("buildExprCheckProtoIP() = %v, want %v", actualExprs, expectedExprs)
	}
}

func TestBuildExprSourceIP(t *testing.T) {
	mockSet := &nftables.Set{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyBridge},
		Name:  "test-src-ip-set",
		ID:    123, /* ID is used by the kernel, but for expr comparison, Name is more relevant if SetID is not used */
	}
	expectedExprs := []expr.Any{
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			DestRegister:  1,
			Base:          expr.PayloadBaseNetworkHeader,
			Offset:        SourceIPOffset,
			Len:           IPLength,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        mockSet.Name,
		},
	}
	actualExprs := testNft.buildExprSourceIP(mockSet)

	if !reflect.DeepEqual(actualExprs, expectedExprs) {
		t.Errorf("buildExprSourceIP() = %#v, want %#v", actualExprs, expectedExprs)
	}
}

func TestBuildExprSourceHW(t *testing.T) {
	mockSet := &nftables.Set{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyBridge},
		Name:  "test-src-hw-set",
		ID:    124,
	}
	expectedExprs := []expr.Any{
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			DestRegister:  1,
			Base:          expr.PayloadBaseLLHeader,
			Offset:        SourceHWOffset,
			Len:           HWLength,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        mockSet.Name,
		},
	}
	actualExprs := testNft.buildExprSourceHW(mockSet)

	if !reflect.DeepEqual(actualExprs, expectedExprs) {
		t.Errorf("buildExprSourceHW() = %#v, want %#v", actualExprs, expectedExprs)
	}
}

func TestBuildExprSourceMask(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected []expr.Any
		wantErr  bool /* To check if we expect a nil due to invalid CIDR */
	}{
		{
			name: "Valid CIDR /24",
			cidr: "192.168.1.0/24",
			expected: []expr.Any{
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: SourceIPOffset, Len: IPLength},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: IPLength, Mask: net.CIDRMask(24, 32), Xor: make([]byte, IPLength)},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: net.ParseIP("192.168.1.0").To4()},
			},
			wantErr: false,
		},
		{
			name: "Valid CIDR /32 (single IP)",
			cidr: "10.0.0.1/32",
			expected: []expr.Any{
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: SourceIPOffset, Len: IPLength},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: IPLength, Mask: net.CIDRMask(32, 32), Xor: make([]byte, IPLength)},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: net.ParseIP("10.0.0.1").To4()},
			},
			wantErr: false,
		},
		{
			name:     "Invalid CIDR - bad format",
			cidr:     "not-a-cidr",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid CIDR - bad IP part",
			cidr:     "192.168.300.0/24",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid CIDR - bad mask part",
			cidr:     "192.168.1.0/33",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "IPv6 CIDR (should be skipped for IPv4 mask)",
			cidr:     "2001:db8::/32",
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualExprs := testNft.buildExprSourceMask(tt.cidr)
			if tt.wantErr {
				if actualExprs != nil {
					t.Errorf("buildExprSourceMask(%s) expected nil due to error, but got %v", tt.cidr, actualExprs)
				}
			} else {
				if !reflect.DeepEqual(actualExprs, tt.expected) {
					/* To make debugging slices of expr.Any easier */
					t.Logf("Actual Expressions for %s:", tt.cidr)
					for i, expr := range actualExprs {
						t.Logf("  Actual[%d]: %#v", i, expr)
					}
					t.Logf("Expected Expressions for %s:", tt.cidr)
					for i, expr := range tt.expected {
						t.Logf("  Expected[%d]: %#v", i, expr)
					}
					t.Errorf("buildExprSourceMask(%s) = Mismatch", tt.cidr)
				}
			}
		})
	}
}

func TestBuildExprDestinationIP(t *testing.T) {
	mockSet := &nftables.Set{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyBridge},
		Name:  "test-dst-ip-set",
		ID:    223,
	}
	expectedExprs := []expr.Any{
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			DestRegister:  1,
			Base:          expr.PayloadBaseNetworkHeader,
			Offset:        DestinationIPOffset,
			Len:           IPLength,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        mockSet.Name,
		},
	}
	actualExprs := testNft.buildExprDestinationIP(mockSet)

	if !reflect.DeepEqual(actualExprs, expectedExprs) {
		t.Errorf("buildExprDestinationIP() = %#v, want %#v", actualExprs, expectedExprs)
	}
}

func TestBuildExprDestinationHW(t *testing.T) {
	mockSet := &nftables.Set{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyBridge},
		Name:  "test-dst-hw-set",
		ID:    224,
	}
	expectedExprs := []expr.Any{
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			DestRegister:  1,
			Base:          expr.PayloadBaseLLHeader,
			Offset:        DestinationHWOffset,
			Len:           HWLength,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        mockSet.Name,
		},
	}
	actualExprs := testNft.buildExprDestinationHW(mockSet)

	if !reflect.DeepEqual(actualExprs, expectedExprs) {
		t.Errorf("buildExprDestinationHW() = %#v, want %#v", actualExprs, expectedExprs)
	}
}

func TestBuildExprDestinationMask(t *testing.T) {
	/* Similar to TestBuildExprSourceMask, but for Destination */
	tests := []struct {
		name     string
		cidr     string
		expected []expr.Any
		wantErr  bool
	}{
		{
			name: "Valid CIDR /16",
			cidr: "10.20.0.0/16",
			expected: []expr.Any{
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: DestinationIPOffset, Len: IPLength},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: IPLength, Mask: net.CIDRMask(16, 32), Xor: make([]byte, IPLength)},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: net.ParseIP("10.20.0.0").To4()},
			},
			wantErr: false,
		},
		{
			name:     "Invalid CIDR - bad format",
			cidr:     "another-invalid-cidr",
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualExprs := testNft.buildExprDestinationMask(tt.cidr)
			if tt.wantErr {
				if actualExprs != nil {
					t.Errorf("buildExprDestinationMask(%s) expected nil due to error, but got %v", tt.cidr, actualExprs)
				}
			} else {
				if !reflect.DeepEqual(actualExprs, tt.expected) {
					t.Logf("Actual Expressions for %s:", tt.cidr)
					for i, exprItem := range actualExprs {
						t.Logf("  Actual[%d]: %#v", i, exprItem)
					}
					t.Logf("Expected Expressions for %s:", tt.cidr)
					for i, exprItem := range tt.expected {
						t.Logf("  Expected[%d]: %#v", i, exprItem)
					}
					t.Errorf("buildExprDestinationMask(%s) = Mismatch", tt.cidr)
				}
			}
		})
	}
}

func TestBuildExprTCPPorts(t *testing.T) {
	mockSet := &nftables.Set{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyBridge},
		Name:  "test-tcp-port-set",
		ID:    300,
	}
	expectedExprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: DestinationPortOffset, Len: PortLength},
		&expr.Lookup{SourceRegister: 1, SetName: mockSet.Name},
	}
	actualExprs := testNft.buildExprTCPPorts(mockSet)

	if !reflect.DeepEqual(actualExprs, expectedExprs) {
		t.Errorf("buildExprTCPPorts() = %#v, want %#v", actualExprs, expectedExprs)
	}
}

func TestBuildExprUDPPorts(t *testing.T) {
	mockSet := &nftables.Set{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyBridge},
		Name:  "test-udp-port-set",
		ID:    301,
	}
	expectedExprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: DestinationPortOffset, Len: PortLength},
		&expr.Lookup{SourceRegister: 1, SetName: mockSet.Name},
	}
	actualExprs := testNft.buildExprUDPPorts(mockSet)

	if !reflect.DeepEqual(actualExprs, expectedExprs) {
		t.Errorf("buildExprUDPPorts() = %#v, want %#v", actualExprs, expectedExprs)
	}
}
