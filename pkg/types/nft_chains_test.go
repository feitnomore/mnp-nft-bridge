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

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestNFTablesChains() *NFTables {
	nft := &NFTables{
		table:         make([]internalTable, 0),
		InternalQueue: make([]QueuedNftOperation, 0),
		conn:          nil,
	}
	/* Added the base table so that search functions can find it. */
	mockTable := &nftables.Table{Name: TableFilter, Family: nftables.TableFamilyBridge}
	nft.table = append(nft.table, internalTable{
		name:   TableFilter,
		table:  mockTable,
		family: nftables.TableFamilyBridge,
	})
	return nft
}

func newTestNFTablesWithBaseChains() *NFTables {
	nft := newTestNFTablesChains()
	mockTable := nft.table[0].table

	/* Add the base chains to the cache */
	nft.table = append(nft.table, internalTable{
		name:   IngressChain,
		chain:  &nftables.Chain{Name: IngressChain, Table: mockTable, Type: nftables.ChainTypeFilter},
		table:  mockTable,
		family: nftables.TableFamilyBridge,
		kind:   nftables.ChainTypeFilter,
		rules:  []nftables.Rule{},
	})
	nft.table = append(nft.table, internalTable{
		name:   EgressChain,
		chain:  &nftables.Chain{Name: EgressChain, Table: mockTable, Type: nftables.ChainTypeFilter},
		table:  mockTable,
		family: nftables.TableFamilyBridge,
		kind:   nftables.ChainTypeFilter,
		rules:  []nftables.Rule{},
	})
	return nft
}

/* Helper to find an operation in the queue (can be moved to a common test helpers file if used in multiple files) */
func findChainsOperation(queue []QueuedNftOperation, opType NftOperationType, nameSubstring string) *QueuedNftOperation {
	for i := range queue {
		op := &queue[i]
		if op.Type == opType {
			var name string
			if op.Table != nil && opType == OpAddTable {
				name = op.Table.Name
			}
			if op.Chain != nil && (opType == OpAddChain || opType == OpDelChain || opType == OpFlushChain) {
				name = op.Chain.Name
			}
			if op.Set != nil && (opType == OpAddSet || opType == OpDelSet || opType == OpFlushSet) {
				name = op.Set.Name
			}
			if opType == OpAddRule || opType == OpDelRule {
				name = op.Description
			} /* For rules, the description may be more useful */

			if strings.Contains(name, nameSubstring) {
				return op
			}
		}
	}
	return nil
}

func TestCreateIngressChain(t *testing.T) {
	nft := newTestNFTablesChains()
	chainSuffix := "testsuffix1"
	expectedChainName := IngressChain + "_" + chainSuffix
	nft.table = append(nft.table, internalTable{
		table: &nftables.Table{Name: TableFilter, Family: nftables.TableFamilyBridge},
	})
	err := nft.CreateIngressChain(chainSuffix, nftables.TableFamilyBridge)
	require.NoError(t, err)
	require.Len(t, nft.InternalQueue, 1, "Expected 1 operation in queue")

	op := nft.InternalQueue[0]
	assert.Equal(t, OpAddChain, op.Type)
	require.NotNil(t, op.Chain)
	assert.Equal(t, expectedChainName, op.Chain.Name)
	require.NotNil(t, op.Chain.Table, "Chain.Table should not be nil")
	assert.Equal(t, TableFilter, op.Chain.Table.Name)
	assert.Equal(t, nftables.TableFamilyBridge, op.Chain.Table.Family)
	assert.Equal(t, nftables.ChainTypeFilter, op.Chain.Type)
	assert.Contains(t, op.Description, "AddChain Ingress")
	assert.Contains(t, op.Description, expectedChainName)
}

func TestCreateEgressChain(t *testing.T) {
	nft := newTestNFTablesChains()
	chainSuffix := "testsuffix2"
	expectedChainName := EgressChain + "_" + chainSuffix
	nft.table = append(nft.table, internalTable{
		table: &nftables.Table{Name: TableFilter, Family: nftables.TableFamilyBridge},
	})
	err := nft.CreateEgressChain(chainSuffix, nftables.TableFamilyBridge)
	require.NoError(t, err)
	require.Len(t, nft.InternalQueue, 1, "Expected 1 operation in queue")

	op := nft.InternalQueue[0]
	assert.Equal(t, OpAddChain, op.Type)
	require.NotNil(t, op.Chain)
	assert.Equal(t, expectedChainName, op.Chain.Name)
	require.NotNil(t, op.Chain.Table, "Chain.Table should not be nil")
	assert.Equal(t, TableFilter, op.Chain.Table.Name)
	assert.Equal(t, nftables.TableFamilyBridge, op.Chain.Table.Family)
	assert.Equal(t, nftables.ChainTypeFilter, op.Chain.Type)
	assert.Contains(t, op.Description, "AddChain Egress")
}

func TestDeletePodSpecificChain(t *testing.T) {
	tests := []struct {
		name                  string
		chainSuffix           string
		chainType             string
		expectedFullChainName string
		wantErr               bool
	}{
		{"Delete Ingress Chain", "suffixIngress", IngressChainType, IngressChain + "_suffixIngress", false},
		{"Delete Egress Chain", "suffixEgress", EgressChainType, EgressChain + "_suffixEgress", false},
		{"Invalid Chain Type", "suffixInvalid", "invalidType", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nft := newTestNFTablesChains()
			nft.table = append(nft.table, internalTable{
				table: &nftables.Table{Name: TableFilter, Family: nftables.TableFamilyBridge},
			})
			err := nft.DeletePodSpecificChain(tt.chainSuffix, tt.chainType)
			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, nft.InternalQueue)
			} else {
				require.NoError(t, err)
				require.Len(t, nft.InternalQueue, 2, "Expected 2 operations: FlushChain and DelChain")
				opFlush := findChainsOperation(nft.InternalQueue, OpFlushChain, tt.expectedFullChainName)
				require.NotNil(t, opFlush, "OpFlushChain not found for %s", tt.expectedFullChainName)
				if opFlush != nil && opFlush.Chain != nil {
					assert.Equal(t, tt.expectedFullChainName, opFlush.Chain.Name)
				}

				opDel := findChainsOperation(nft.InternalQueue, OpDelChain, tt.expectedFullChainName)
				require.NotNil(t, opDel, "OpDelChain not found for %s", tt.expectedFullChainName)
				if opDel != nil && opDel.Chain != nil {
					assert.Equal(t, tt.expectedFullChainName, opDel.Chain.Name)
				}
			}
		})
	}
}

func TestCleanupPodNftResources(t *testing.T) {
	chainSuffix := "cleanupSuffix"
	podMac := "00:11:22:33:44:55"
	macBytes, errParseMac := net.ParseMAC(podMac)
	require.NoError(t, errParseMac, "Failed to parse mock MAC address")

	ingressFullChain := IngressChain + "_" + chainSuffix
	egressFullChain := EgressChain + "_" + chainSuffix

	tests := []struct {
		name                     string
		chainType                string
		fullChainNameToDelete    string
		isIsolationChain         bool
		policySpecificRuleCount  int
		expectedSetDeletionCount int
		hwOffsetForJump          uint32
		baseChainNameForJump     string
	}{
		{
			name:                     "Cleanup Ingress Rule Chain (2 MNP rules)",
			chainType:                IngressChainType,
			fullChainNameToDelete:    ingressFullChain,
			isIsolationChain:         false,
			policySpecificRuleCount:  2,
			expectedSetDeletionCount: 2 * 4,
			hwOffsetForJump:          DestinationHWOffset,
			baseChainNameForJump:     IngressChain,
		},
		{
			name:                     "Cleanup Egress Rule Chain (1 MNP rule)",
			chainType:                EgressChainType,
			fullChainNameToDelete:    egressFullChain,
			isIsolationChain:         false,
			policySpecificRuleCount:  1,
			expectedSetDeletionCount: 1 * 4,
			hwOffsetForJump:          SourceHWOffset,
			baseChainNameForJump:     EgressChain,
		},
		{
			name:                     "Cleanup Ingress Isolation Chain",
			chainType:                IngressChainType,
			fullChainNameToDelete:    IngressChain + "_ISOLATION_" + chainSuffix,
			isIsolationChain:         true,
			policySpecificRuleCount:  0,
			expectedSetDeletionCount: 0,
			hwOffsetForJump:          DestinationHWOffset,
			baseChainNameForJump:     IngressChain,
		},
		{
			name:                     "Cleanup Ingress Rule Chain (0 MNP rules)",
			chainType:                IngressChainType,
			fullChainNameToDelete:    ingressFullChain,
			isIsolationChain:         false,
			policySpecificRuleCount:  0,
			expectedSetDeletionCount: 0,
			hwOffsetForJump:          DestinationHWOffset,
			baseChainNameForJump:     IngressChain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nft := newTestNFTablesWithBaseChains()
			mockTable := nft.table[0].table

			/* Pre-populate cache with rules that are expected to be deleted */
			jumpRuleExprs := []expr.Any{
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: tt.hwOffsetForJump, Len: HWLength},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: macBytes},
				&expr.Verdict{Kind: expr.VerdictJump, Chain: tt.fullChainNameToDelete},
			}
			ingressDropExprs := []expr.Any{
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: DestinationHWOffset, Len: HWLength},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: macBytes},
				&expr.Verdict{Kind: expr.VerdictDrop},
			}
			egressDropExprs := []expr.Any{
				&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: SourceHWOffset, Len: HWLength},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: macBytes},
				&expr.Verdict{Kind: expr.VerdictDrop},
			}

			/* Add rules to the respective base chains in the mock cache */
			for i := range nft.table {
				if nft.table[i].chain != nil {
					if nft.table[i].chain.Name == tt.baseChainNameForJump {
						nft.table[i].rules = append(nft.table[i].rules, nftables.Rule{Table: mockTable, Chain: nft.table[i].chain, Exprs: jumpRuleExprs, Handle: 100})
					}
					if nft.table[i].chain.Name == IngressChain {
						nft.table[i].rules = append(nft.table[i].rules, nftables.Rule{Table: mockTable, Chain: nft.table[i].chain, Exprs: ingressDropExprs, Handle: 200})
					}
					if nft.table[i].chain.Name == EgressChain {
						nft.table[i].rules = append(nft.table[i].rules, nftables.Rule{Table: mockTable, Chain: nft.table[i].chain, Exprs: egressDropExprs, Handle: 300})
					}
				}
			}

			/* Execute the function under test */
			err := nft.CleanupPodNftResources(podMac, tt.chainType, tt.fullChainNameToDelete, chainSuffix, tt.isIsolationChain, tt.policySpecificRuleCount)
			require.NoError(t, err)

			/* 1 (del jump) + 2 (flush/del chain) + N (sets) + 1 (del ingress drop) + 1 (del egress drop) */
			expectedTotalOps := 1 + 2 + tt.expectedSetDeletionCount + 1 + 1
			assert.Len(t, nft.InternalQueue, expectedTotalOps, "Incorrect number of total operations in the queue.")

			/* Verify each operation type is present */
			assert.NotNil(t, findChainsOperation(nft.InternalQueue, OpDelRule, "JumpOnly"), "OpDelRule for jump not queued")
			assert.NotNil(t, findChainsOperation(nft.InternalQueue, OpFlushChain, tt.fullChainNameToDelete), "OpFlushChain for %s not queued", tt.fullChainNameToDelete)
			assert.NotNil(t, findChainsOperation(nft.InternalQueue, OpDelChain, tt.fullChainNameToDelete), "OpDelChain for %s not queued", tt.fullChainNameToDelete)
			assert.NotNil(t, findChainsOperation(nft.InternalQueue, OpDelRule, "ingress drop"), "OpDelRule for ingress drop not queued")
			assert.NotNil(t, findChainsOperation(nft.InternalQueue, OpDelRule, "egress drop"), "OpDelRule for egress drop not queued")

			actualSetDeletionCount := 0
			for _, op := range nft.InternalQueue {
				if op.Type == OpDelSet {
					actualSetDeletionCount++
				}
			}
			assert.Equal(t, tt.expectedSetDeletionCount, actualSetDeletionCount, "Incorrect number of OpDelSet operations")
		})
	}
}
