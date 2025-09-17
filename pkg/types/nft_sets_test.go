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
	"strings"
	"testing"

	"github.com/feitnomore/mnp-nft-bridge/pkg/utils"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestNFTablesForSets() *NFTables {
	nft := &NFTables{
		table:         make([]internalTable, 0),
		InternalQueue: make([]QueuedNftOperation, 0),
		conn:          nil, /* conn is not used directly by enqueue methods */
	}
	/* Add the 'filter' table from the 'bridge' family to the internal cache,
	 * since the build*Set and deleteNftSet functions expect to find it there.
	 */
	mockTable := &nftables.Table{Name: TableFilter, Family: nftables.TableFamilyBridge}
	nft.table = append(nft.table, internalTable{
		name:   TableFilter, /* Table name */
		table:  mockTable,
		family: nftables.TableFamilyBridge,
	})
	return nft
}

/* Helper to find an OpAddSet operation in the queue and check its elements */
func findAddSetOperation(t *testing.T, queue []QueuedNftOperation, setNameSubstring string) (*QueuedNftOperation, []nftables.SetElement) {
	t.Helper()
	for i := range queue {
		op := &queue[i]
		if op.Type == OpAddSet && op.Set != nil && strings.Contains(op.Set.Name, setNameSubstring) {
			return op, op.SetElements
		}
	}
	return nil, nil
}

/* Helper to find an OpFlushSet operation in the queue */
func findFlushSetOperation(t *testing.T, queue []QueuedNftOperation, setNameSubstring string) *QueuedNftOperation {
	t.Helper()
	for i := range queue {
		op := &queue[i]
		if op.Type == OpFlushSet && op.Set != nil && strings.Contains(op.Set.Name, setNameSubstring) {
			return op
		}
	}
	return nil
}

/* Helper to find an OpDelSet operation in the queue */
func findDelSetOperation(t *testing.T, queue []QueuedNftOperation, setNameSubstring string) *QueuedNftOperation {
	t.Helper()
	for i := range queue {
		op := &queue[i]
		if op.Type == OpDelSet && op.Set != nil && strings.Contains(op.Set.Name, setNameSubstring) {
			return op
		}
	}
	return nil
}

func TestBuildPortSet(t *testing.T) {
	nft := newTestNFTablesForSets()
	chainSuffix := "suffix123"
	ruleDirection := string(NftRuleDirectionIngress)
	ruleIndex := 0
	ports := []uint16{80, 443}
	setType := NftSetTypeTCPPort

	expectedSetIDStr := utils.GenerateDeterministicSetID(chainSuffix, ruleDirection, ruleIndex, string(setType))
	expectedSetName := "mnp-" + string(setType) + "-" + expectedSetIDStr[:setSize]

	returnedSet := nft.buildPortSet(chainSuffix, ruleDirection, ruleIndex, setType, ports)

	require.NotNil(t, returnedSet, "buildPortSet should return a non-nil set object")
	assert.Equal(t, expectedSetName, returnedSet.Name)
	assert.Equal(t, nftables.TypeInetService, returnedSet.KeyType)
	assert.Equal(t, TableFilter, returnedSet.Table.Name)
	assert.Equal(t, nftables.TableFamilyBridge, returnedSet.Table.Family)

	require.Len(t, nft.InternalQueue, 2, "Expected 2 operations: OpFlushSet and OpAddSet")

	flushOp := findFlushSetOperation(t, nft.InternalQueue, expectedSetName)
	require.NotNil(t, flushOp, "OpFlushSet not found for %s", expectedSetName)
	assert.Equal(t, expectedSetName, flushOp.Set.Name)

	addOp, addElements := findAddSetOperation(t, nft.InternalQueue, expectedSetName)
	require.NotNil(t, addOp, "OpAddSet not found for %s", expectedSetName)
	assert.Equal(t, expectedSetName, addOp.Set.Name)
	require.Len(t, addElements, len(ports), "Incorrect number of elements in OpAddSet")

	expectedElements := []nftables.SetElement{
		{Key: binaryutil.BigEndian.PutUint16(80)},
		{Key: binaryutil.BigEndian.PutUint16(443)},
	}
	assert.ElementsMatch(t, expectedElements, addElements, "Set elements do not match")

	/* Test with empty port slice */
	nft.InternalQueue = nil /* Clear queue */
	emptyPorts := []uint16{}
	returnedEmptySet := nft.buildPortSet(chainSuffix, ruleDirection, ruleIndex, setType, emptyPorts)
	require.NotNil(t, returnedEmptySet)
	flushOpEmpty := findFlushSetOperation(t, nft.InternalQueue, expectedSetName)
	require.NotNil(t, flushOpEmpty)
	addOpEmpty, addElementsEmpty := findAddSetOperation(t, nft.InternalQueue, expectedSetName)
	require.NotNil(t, addOpEmpty)
	assert.Empty(t, addElementsEmpty, "Expected no elements when ports slice is empty")
}

func TestBuildIPSet(t *testing.T) {
	nft := newTestNFTablesForSets()
	chainSuffix := "suffixIP"
	ruleDirection := string(NftRuleDirectionEgress)
	ruleIndex := 1
	sources := []string{"192.168.1.10", "10.0.0.0/24", "172.16.5.5", "invalid-ip", "2001:db8::1/32"} /* Includes invalid IP and IPv6 */
	setType := NftSetTypeDstIP

	expectedSetIDStr := utils.GenerateDeterministicSetID(chainSuffix, ruleDirection, ruleIndex, string(setType))
	expectedSetName := "mnp-" + string(setType) + "-" + expectedSetIDStr[:setSize]

	returnedSet, cidrList, hasValidSingles := nft.buildIPSet(chainSuffix, ruleDirection, ruleIndex, setType, sources)

	require.NotNil(t, returnedSet, "buildIPSet should return a non-nil set object")
	assert.Equal(t, expectedSetName, returnedSet.Name)
	assert.Equal(t, nftables.TypeIPAddr, returnedSet.KeyType)
	assert.True(t, hasValidSingles, "hasValidSingles should be true")

	require.Len(t, nft.InternalQueue, 2, "Expected 2 operations: OpFlushSet and OpAddSet")

	flushOp := findFlushSetOperation(t, nft.InternalQueue, expectedSetName)
	require.NotNil(t, flushOp)

	addOp, addElements := findAddSetOperation(t, nft.InternalQueue, expectedSetName)
	require.NotNil(t, addOp)

	expectedIPsInSet := []net.IP{net.ParseIP("192.168.1.10").To4(), net.ParseIP("172.16.5.5").To4()}
	require.Len(t, addElements, len(expectedIPsInSet), "Incorrect number of IP elements in OpAddSet")
	var actualIPsInSet []net.IP
	for _, el := range addElements {
		actualIPsInSet = append(actualIPsInSet, net.IP(el.Key))
	}
	assert.ElementsMatch(t, expectedIPsInSet, actualIPsInSet, "IP elements in set do not match")

	/* CIDRs that were not set (10.0.0.0/24 and IPv6 for logging)
	 * "invalid-ip" is skipped completely
	 */
	expectedCidrList := []string{"10.0.0.0/24", "2001:db8::1/32"}
	assert.ElementsMatch(t, expectedCidrList, cidrList, "CIDR list does not match")

	/* Test with only CIDRs */
	nft.InternalQueue = nil
	sourcesOnlyCidrs := []string{"10.1.0.0/16", "10.2.0.0/16"}
	_, cidrListOnly, hasValidSinglesOnlyCidrs := nft.buildIPSet(chainSuffix, ruleDirection, 2, setType, sourcesOnlyCidrs)
	assert.False(t, hasValidSinglesOnlyCidrs, "hasValidSingles should be false when only CIDRs are provided")
	assert.ElementsMatch(t, sourcesOnlyCidrs, cidrListOnly)
	_, addElementsOnlyCidrs := findAddSetOperation(t, nft.InternalQueue, "mnp-dst-ip-") /* Set name will be different */
	assert.Empty(t, addElementsOnlyCidrs, "Set elements should be empty if only CIDRs are provided")
}

func TestBuildHWSet(t *testing.T) {
	nft := newTestNFTablesForSets()
	chainSuffix := "suffixHW"
	ruleDirection := string(NftRuleDirectionIngress)
	ruleIndex := 2
	sources := []string{"00:1A:2B:3C:4D:5E", "aa:bb:cc:dd:ee:ff", "invalid-mac"}
	setType := NftSetTypeSrcMAC

	expectedSetIDStr := utils.GenerateDeterministicSetID(chainSuffix, ruleDirection, ruleIndex, string(setType))
	expectedSetName := "mnp-" + string(setType) + "-" + expectedSetIDStr[:setSize]

	returnedSet := nft.buildHWSet(chainSuffix, ruleDirection, ruleIndex, setType, sources)

	require.NotNil(t, returnedSet, "buildHWSet should return a non-nil set object")
	assert.Equal(t, expectedSetName, returnedSet.Name)
	assert.Equal(t, nftables.TypeEtherAddr, returnedSet.KeyType)

	require.Len(t, nft.InternalQueue, 2, "Expected 2 operations: OpFlushSet and OpAddSet")

	flushOp := findFlushSetOperation(t, nft.InternalQueue, expectedSetName)
	require.NotNil(t, flushOp)

	addOp, addElements := findAddSetOperation(t, nft.InternalQueue, expectedSetName)
	require.NotNil(t, addOp)

	mac1, _ := net.ParseMAC("00:1A:2B:3C:4D:5E")
	mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	expectedHWElements := []nftables.SetElement{
		{Key: mac1},
		{Key: mac2},
	}
	require.Len(t, addElements, len(expectedHWElements), "Incorrect number of HW elements in OpAddSet")

	var actualHWElements []net.HardwareAddr
	for _, el := range addElements {
		actualHWElements = append(actualHWElements, net.HardwareAddr(el.Key))
	}
	assert.ElementsMatch(t, []net.HardwareAddr{mac1, mac2}, actualHWElements, "HW elements in set do not match")
}

func TestBuildTCPPortSet(t *testing.T) {
	nft := newTestNFTablesForSets()
	chainSuffix := "suffixTCP"
	ruleDirection := string(NftRuleDirectionEgress)
	ruleIndex := 3
	ports := []uint16{8080, 9090}

	expectedSetIDStr := utils.GenerateDeterministicSetID(chainSuffix, ruleDirection, ruleIndex, string(NftSetTypeTCPPort))
	expectedSetName := "mnp-" + string(NftSetTypeTCPPort) + "-" + expectedSetIDStr[:setSize]

	returnedSet := nft.buildTCPPortSet(chainSuffix, ruleDirection, ruleIndex, ports)
	require.NotNil(t, returnedSet)
	assert.Equal(t, expectedSetName, returnedSet.Name)
	assert.Equal(t, nftables.TypeInetService, returnedSet.KeyType)

	/* The internal logic is tested by TestBuildPortSet, here we just check the wrapper */
	require.Len(t, nft.InternalQueue, 2)
	flushOp := findFlushSetOperation(t, nft.InternalQueue, expectedSetName)
	require.NotNil(t, flushOp)
	addOp, _ := findAddSetOperation(t, nft.InternalQueue, expectedSetName)
	require.NotNil(t, addOp)
}

func TestBuildUDPPortSet(t *testing.T) {
	nft := newTestNFTablesForSets()
	chainSuffix := "suffixUDP"
	ruleDirection := string(NftRuleDirectionIngress)
	ruleIndex := 4
	ports := []uint16{53, 5353}

	expectedSetIDStr := utils.GenerateDeterministicSetID(chainSuffix, ruleDirection, ruleIndex, string(NftSetTypeUDPPort))
	expectedSetName := "mnp-" + string(NftSetTypeUDPPort) + "-" + expectedSetIDStr[:setSize]

	returnedSet := nft.buildUDPPortSet(chainSuffix, ruleDirection, ruleIndex, ports)
	require.NotNil(t, returnedSet)
	assert.Equal(t, expectedSetName, returnedSet.Name)
	assert.Equal(t, nftables.TypeInetService, returnedSet.KeyType)

	require.Len(t, nft.InternalQueue, 2)
	flushOp := findFlushSetOperation(t, nft.InternalQueue, expectedSetName)
	require.NotNil(t, flushOp)
	addOp, _ := findAddSetOperation(t, nft.InternalQueue, expectedSetName)
	require.NotNil(t, addOp)
}

func TestDeleteNftSet(t *testing.T) {
	nft := newTestNFTablesForSets()
	chainSuffix := "suffixDel"
	ruleDirection := string(NftRuleDirectionIngress)
	ruleIndex := 5

	tests := []struct {
		setType      NftSetType
		expectedType nftables.SetDatatype
	}{
		{NftSetTypeSrcIP, nftables.TypeIPAddr},
		{NftSetTypeDstMAC, nftables.TypeEtherAddr},
		{NftSetTypeTCPPort, nftables.TypeInetService},
	}

	for _, tt := range tests {
		t.Run(string(tt.setType), func(t *testing.T) {
			nft.InternalQueue = nil /* Clear queue for each subtest */

			expectedSetIDStr := utils.GenerateDeterministicSetID(chainSuffix, ruleDirection, ruleIndex, string(tt.setType))
			expectedSetName := "mnp-" + string(tt.setType) + "-" + expectedSetIDStr[:setSize]

			nft.deleteNftSet(chainSuffix, ruleDirection, ruleIndex, string(tt.setType))

			require.Len(t, nft.InternalQueue, 1, "Expected 1 OpDelSet operation")
			delOp := findDelSetOperation(t, nft.InternalQueue, expectedSetName)
			require.NotNil(t, delOp, "OpDelSet not found for %s", expectedSetName)
			assert.Equal(t, expectedSetName, delOp.Set.Name)
			assert.Equal(t, tt.expectedType, delOp.Set.KeyType)
			assert.Equal(t, TableFilter, delOp.Set.Table.Name)
			assert.Equal(t, nftables.TableFamilyBridge, delOp.Set.Table.Family)
		})
	}
}
