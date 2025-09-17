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

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

func (nft *NFTables) buildExprCheckProtoIP() []expr.Any {
	thisExpr := []expr.Any{
		&expr.Meta{
			Key:            expr.MetaKeyPROTOCOL, /* Getting Protocol */
			SourceRegister: false,
			Register:       1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(unix.ETH_P_IP), /* unix.ETH_P_IPV6 */
		},
	}
	return thisExpr
}

func (nft *NFTables) buildExprSourceIP(thisSet *nftables.Set) []expr.Any {
	payloadExpr := &expr.Payload{
		OperationType:  expr.PayloadLoad,
		DestRegister:   1,
		SourceRegister: 0,
		Base:           expr.PayloadBaseNetworkHeader,
		Offset:         SourceIPOffset, /* Source IP */
		Len:            IPLength,
		CsumType:       0,
		CsumOffset:     0,
		CsumFlags:      0,
	}

	lookupExpr := &expr.Lookup{
		SourceRegister: 1,
		SetName:        thisSet.Name, /* Rely on the name for resolution */
	}

	thisExpr := []expr.Any{
		payloadExpr,
		lookupExpr,
	}

	return thisExpr
}

func (nft *NFTables) buildExprSourceHW(thisSet *nftables.Set) []expr.Any {
	payloadExpr := &expr.Payload{
		OperationType:  expr.PayloadLoad,
		DestRegister:   1,
		SourceRegister: 0,
		Base:           expr.PayloadBaseLLHeader,
		Offset:         SourceHWOffset, /* Source HW */
		Len:            HWLength,
	}

	lookupExpr := &expr.Lookup{
		SourceRegister: 1,
		SetName:        thisSet.Name,
	}

	thisExpr := []expr.Any{
		payloadExpr,
		lookupExpr,
	}

	return thisExpr
}

func (nft *NFTables) buildExprSourceMask(thisCidr string) []expr.Any {
	srcIP, srcMask, err := net.ParseCIDR(thisCidr)
	if err != nil {
		klog.Warningf("Error parsing CIDR '%s' for source mask rule: %v. Skipping this mask rule.", thisCidr, err)
		return nil
	}
	ipv4 := srcIP.To4()
	if ipv4 == nil {
		klog.Warningf("Source IP from CIDR '%s' is not an IPv4 address for mask rule. Skipping this mask rule.", thisCidr)
		return nil
	}

	thisExpr := []expr.Any{
		&expr.Payload{
			OperationType:  expr.PayloadLoad,
			DestRegister:   1,
			SourceRegister: 0,
			Base:           expr.PayloadBaseNetworkHeader,
			Offset:         SourceIPOffset,
			Len:            IPLength,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            IPLength,
			Mask:           srcMask.Mask,
			Xor:            make([]byte, IPLength),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ipv4,
		},
	}
	return thisExpr
}

func (nft *NFTables) buildExprDestinationIP(thisSet *nftables.Set) []expr.Any {
	payloadExpr := &expr.Payload{
		OperationType:  expr.PayloadLoad,
		DestRegister:   1,
		SourceRegister: 0,
		Base:           expr.PayloadBaseNetworkHeader,
		Offset:         DestinationIPOffset, // Destination IP
		Len:            IPLength,
	}

	lookupExpr := &expr.Lookup{
		SourceRegister: 1,
		SetName:        thisSet.Name,
	}

	thisExpr := []expr.Any{
		payloadExpr,
		lookupExpr,
	}

	return thisExpr
}

func (nft *NFTables) buildExprDestinationHW(thisSet *nftables.Set) []expr.Any {
	payloadExpr := &expr.Payload{
		OperationType:  expr.PayloadLoad,
		DestRegister:   1,
		SourceRegister: 0,
		Base:           expr.PayloadBaseLLHeader,
		Offset:         DestinationHWOffset, /* Destination HW */
		Len:            HWLength,
	}

	lookupExpr := &expr.Lookup{
		SourceRegister: 1,
		SetName:        thisSet.Name,
	}

	thisExpr := []expr.Any{
		payloadExpr,
		lookupExpr,
	}

	return thisExpr
}

func (nft *NFTables) buildExprDestinationMask(thisCidr string) []expr.Any {
	dstIP, dstMask, err := net.ParseCIDR(thisCidr)
	if err != nil {
		klog.Warningf("Error parsing CIDR '%s' for destination mask rule: %v. Skipping this mask rule.", thisCidr, err)
		return nil
	}
	ipv4 := dstIP.To4()
	if ipv4 == nil {
		klog.Warningf("Destination IP from CIDR '%s' is not an IPv4 address for mask rule. Skipping this mask rule.", thisCidr)
		return nil
	}

	thisExpr := []expr.Any{
		&expr.Payload{
			OperationType:  expr.PayloadLoad,
			DestRegister:   1,
			SourceRegister: 0,
			Base:           expr.PayloadBaseNetworkHeader,
			Offset:         DestinationIPOffset,
			Len:            IPLength,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            IPLength,
			Mask:           dstMask.Mask,
			Xor:            make([]byte, IPLength),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ipv4,
		},
	}
	return thisExpr
}

func (nft *NFTables) buildExprTCPPorts(thisSet *nftables.Set) []expr.Any {
	metaExpr := &expr.Meta{
		Key:            expr.MetaKeyL4PROTO, /* L4 PROTOCOL */
		SourceRegister: false,
		Register:       1,
	}
	cmpExpr := &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte{unix.IPPROTO_TCP}, /*) TCP Protocol */
	}
	payloadExpr := &expr.Payload{
		OperationType:  expr.PayloadLoad,
		DestRegister:   1, /* This DestRegister will be overwritten by the port payload */
		SourceRegister: 0,
		Base:           expr.PayloadBaseTransportHeader,
		Offset:         DestinationPortOffset, /* DESTINATION PORT */
		Len:            PortLength,
	}

	lookupExpr := &expr.Lookup{
		SourceRegister: 1, /* Must match the DestRegister of the Payload that carries the port */
		SetName:        thisSet.Name,
	}

	thisExpr := []expr.Any{
		metaExpr,    /* Reg 1 = L4 Proto                               */
		cmpExpr,     /* Compare Reg 1 with TCP                         */
		payloadExpr, /* Reg 1 = Destination Port (overwrites L4 Proto) */
		lookupExpr,  /* Search Reg 1 (Destination Port) in the set     */
	}
	return thisExpr
}

func (nft *NFTables) buildExprUDPPorts(thisSet *nftables.Set) []expr.Any {
	metaExpr := &expr.Meta{
		Key:            expr.MetaKeyL4PROTO, /* L4 PROTOCOL */
		SourceRegister: false,
		Register:       1,
	}
	cmpExpr := &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     []byte{unix.IPPROTO_UDP}, /* UDP Protocol */
	}
	payloadExpr := &expr.Payload{
		OperationType:  expr.PayloadLoad,
		DestRegister:   1,
		SourceRegister: 0,
		Base:           expr.PayloadBaseTransportHeader,
		Offset:         DestinationPortOffset, /* DESTINATION PORT */
		Len:            PortLength,
	}

	lookupExpr := &expr.Lookup{
		SourceRegister: 1,
		SetName:        thisSet.Name,
	}

	thisExpr := []expr.Any{
		metaExpr,
		cmpExpr,
		payloadExpr,
		lookupExpr,
	}
	return thisExpr
}
