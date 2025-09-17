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
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/feitnomore/mnp-nft-bridge/pkg/utils"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/* newTestNFTablesWithBaseInfra is a helper to create an NFTables instance
 * with a mockTable already added to the internal nft.table cache,
 * and the base chains IngressChain and EgressChain also added to the cache.
 */
func newTestNFTablesWithBaseInfra() *NFTables {
	nft := &NFTables{
		table:         make([]internalTable, 0),
		InternalQueue: make([]QueuedNftOperation, 0),
		conn:          nil,
	}
	mockTable := &nftables.Table{Name: TableFilter, Family: nftables.TableFamilyBridge}
	nft.table = append(nft.table, internalTable{table: mockTable})

	nft.table = append(nft.table, internalTable{
		chain:  &nftables.Chain{Name: IngressChain, Table: mockTable, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting},
		table:  mockTable,
		family: nftables.TableFamilyBridge,
		rules:  []nftables.Rule{},
	})
	nft.table = append(nft.table, internalTable{
		chain:  &nftables.Chain{Name: EgressChain, Table: mockTable, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting},
		table:  mockTable,
		family: nftables.TableFamilyBridge,
		rules:  []nftables.Rule{},
	})
	return nft
}

func TestEnqueueDeleteBridgeRuleJumpOnly(t *testing.T) {
	podMac := "00:11:22:33:44:BB"
	parentChainName := IngressChain
	targetPodChainName := IngressChain + "_deletetarget"
	var hwOffset uint32 = DestinationHWOffset

	macBytes, errMac := utils.ParseMAC(podMac)
	require.NoError(t, errMac)

	expectedExprsForJump := []expr.Any{
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, SourceRegister: 0, Base: expr.PayloadBaseLLHeader, Offset: hwOffset, Len: HWLength, CsumType: 0, CsumOffset: 0, CsumFlags: 0},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: macBytes},
		&expr.Verdict{Kind: expr.VerdictJump, Chain: targetPodChainName},
	}
	t.Logf("DEBUG_TEST_SETUP (TestEnqueueDeleteBridgeRuleJumpOnly): Signature for expected jump expressions (used in mock): %s", utils.NormalizeExprsForComparison(expectedExprsForJump))

	t.Run("JumpRuleExistsInCache", func(t *testing.T) {
		nft := newTestNFTablesWithBaseInfra()

		parentChainEntryIndex := -1
		for i := range nft.table {
			if nft.table[i].chain != nil && nft.table[i].chain.Name == parentChainName {
				parentChainEntryIndex = i
				break
			}
		}
		require.NotEqual(t, -1, parentChainEntryIndex, "Parent chain entry for jump rule not found in mock table by index")
		if nft.table[parentChainEntryIndex].rules == nil {
			nft.table[parentChainEntryIndex].rules = []nftables.Rule{}
		}

		mockedRule := nftables.Rule{
			Table:  nft.table[parentChainEntryIndex].chain.Table,
			Chain:  nft.table[parentChainEntryIndex].chain,
			Handle: 54321,
			Exprs:  expectedExprsForJump,
		}
		nft.table[parentChainEntryIndex].rules = append(nft.table[parentChainEntryIndex].rules, mockedRule)
		t.Logf("DEBUG_TEST (JumpRuleExistsInCache): Added mock rule to nft.table[%d].rules. Its signature: %s",
			parentChainEntryIndex, utils.NormalizeExprsForComparison(nft.table[parentChainEntryIndex].rules[0].Exprs))

		nft.EnqueueDeleteBridgeRuleJumpOnly(parentChainName, targetPodChainName, podMac, hwOffset)

		require.Len(t, nft.InternalQueue, 1, "Expected 1 OpDelRule operation")
		op := nft.InternalQueue[0]
		assert.Equal(t, OpDelRule, op.Type)
		require.NotNil(t, op.Rule)
		assert.Equal(t, mockedRule.Handle, op.Rule.Handle, "Deletion rule handle does not match mock")
		assert.Contains(t, op.Description, fmt.Sprintf("Handle %d", mockedRule.Handle))
		assert.Contains(t, op.Description, podMac)
		assert.Contains(t, op.Description, targetPodChainName)
	})

	t.Run("JumpRuleNotExistsInCache", func(t *testing.T) {
		nft := newTestNFTablesWithBaseInfra()
		nft.EnqueueDeleteBridgeRuleJumpOnly(parentChainName, targetPodChainName, podMac, hwOffset)
		assert.Len(t, nft.InternalQueue, 0, "Expected 0 OpDelRule operations when rule not in cache")
	})

	t.Run("ParentChainNotExistsInCache", func(t *testing.T) {
		nftSimple := &NFTables{
			table:         make([]internalTable, 0),
			InternalQueue: make([]QueuedNftOperation, 0),
			conn:          nil,
		}
		nftSimple.table = append(nftSimple.table, internalTable{table: &nftables.Table{Name: TableFilter, Family: nftables.TableFamilyBridge}})
		nftSimple.EnqueueDeleteBridgeRuleJumpOnly(parentChainName, targetPodChainName, podMac, hwOffset)
		assert.Len(t, nftSimple.InternalQueue, 0, "Expected 0 OpDelRule operations when parent chain not in cache")
	})
}

func TestEnqueueDeleteDropRules(t *testing.T) {
	podMac := "00:11:22:33:44:CC"
	macBytes, _ := utils.ParseMAC(podMac)

	tests := []struct {
		name              string
		deleteFunc        func(nft *NFTables, mac string)
		baseChainName     string
		hwOffset          uint32
		expectedDescParts []string
		mockHandle        uint64
	}{
		{
			name:              "DeleteIngressDropRule - Rule Exists",
			deleteFunc:        (*NFTables).EnqueueDeleteIngressDropRule,
			baseChainName:     IngressChain,
			hwOffset:          DestinationHWOffset,
			expectedDescParts: []string{"DelRule", fmt.Sprintf("Handle %d", uint64(67890)), "ingress drop", podMac, IngressChain},
			mockHandle:        67890,
		},
		{
			name:              "DeleteEgressDropRule - Rule Exists",
			deleteFunc:        (*NFTables).EnqueueDeleteEgressDropRule,
			baseChainName:     EgressChain,
			hwOffset:          SourceHWOffset,
			expectedDescParts: []string{"DelRule", fmt.Sprintf("Handle %d", uint64(67891)), "egress drop", podMac, EgressChain},
			mockHandle:        67891,
		},
		{
			name:          "DeleteIngressDropRule - Rule Not In Cache",
			deleteFunc:    (*NFTables).EnqueueDeleteIngressDropRule,
			baseChainName: IngressChain,
			hwOffset:      DestinationHWOffset,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nft := newTestNFTablesWithBaseInfra()

			if strings.Contains(tt.name, "Rule Exists") {
				parentChainEntryIndex := -1
				for i := range nft.table {
					if nft.table[i].chain != nil && nft.table[i].chain.Name == tt.baseChainName {
						parentChainEntryIndex = i
						break
					}
				}
				require.NotEqual(t, -1, parentChainEntryIndex, "Base chain entry for drop rule not found in mock table by index")
				if nft.table[parentChainEntryIndex].rules == nil {
					nft.table[parentChainEntryIndex].rules = []nftables.Rule{}
				}

				dropExprs := []expr.Any{
					&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, SourceRegister: 0, Base: expr.PayloadBaseLLHeader, Offset: tt.hwOffset, Len: HWLength, CsumType: 0, CsumOffset: 0, CsumFlags: 0},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: macBytes},
					&expr.Verdict{Kind: expr.VerdictDrop},
				}
				mockedRule := nftables.Rule{
					Table:  nft.table[parentChainEntryIndex].chain.Table,
					Chain:  nft.table[parentChainEntryIndex].chain,
					Handle: tt.mockHandle,
					Exprs:  dropExprs,
				}
				nft.table[parentChainEntryIndex].rules = append(nft.table[parentChainEntryIndex].rules, mockedRule)
				t.Logf("DEBUG_TEST (%s): Added mock drop rule with signature: %s", tt.name, utils.NormalizeExprsForComparison(mockedRule.Exprs))
			}

			tt.deleteFunc(nft, podMac)

			if strings.Contains(tt.name, "Rule Exists") {
				require.Len(t, nft.InternalQueue, 1, "Expected 1 OpDelRule operation when rule exists in cache")
				op := nft.InternalQueue[0]
				assert.Equal(t, OpDelRule, op.Type)
				for _, keyword := range tt.expectedDescParts {
					assert.Contains(t, op.Description, keyword, "Description '%s' should contain '%s'", op.Description, keyword)
				}
				if op.Rule != nil {
					assert.Equal(t, tt.mockHandle, op.Rule.Handle, "Deletion rule handle does not match mock")
				}
			} else {
				assert.Len(t, nft.InternalQueue, 0, "Expected 0 OpDelRule operations when rule not in cache")
			}
		})
	}
}

func TestEnsurePodDropRules(t *testing.T) {
	podMac := "00:11:22:33:44:DD"

	tests := []struct {
		name              string
		ensureFunc        func(nft *NFTables, mac string)
		baseChainName     string
		expectedDescParts []string
	}{
		{
			name:              "EnsurePodIngressDropRule",
			ensureFunc:        (*NFTables).EnsurePodIngressDropRule,
			baseChainName:     IngressChain,
			expectedDescParts: []string{"AddRule", "EnsurePodIngressDropRule", podMac},
		},
		{
			name:              "EnsurePodEgressDropRule",
			ensureFunc:        (*NFTables).EnsurePodEgressDropRule,
			baseChainName:     EgressChain,
			expectedDescParts: []string{"AddRule", "EnsurePodEgressDropRule", podMac},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nft := newTestNFTablesWithBaseInfra()
			tt.ensureFunc(nft, podMac)

			delRuleOps := 0
			for _, op := range nft.InternalQueue {
				if op.Type == OpDelRule {
					delRuleOps++
				}
			}

			addRuleOps := 0
			var addRuleOp *QueuedNftOperation
			for _, op := range nft.InternalQueue {
				if op.Type == OpAddRule {
					addRuleOps++
					addRuleOp = &op
				}
			}

			assert.Equal(t, 0, delRuleOps, "Should not queue OpDelRule as the rule does not exist in the cache to be deleted first")
			assert.Equal(t, 1, addRuleOps, "Should enqueue exactly one OpAddRule")

			if addRuleOp != nil {
				for _, keyword := range tt.expectedDescParts {
					assert.Contains(t, addRuleOp.Description, keyword)
				}
				require.NotNil(t, addRuleOp.Rule)
				assert.Equal(t, tt.baseChainName, addRuleOp.Rule.Chain.Name)
				require.True(t, len(addRuleOp.Rule.Exprs) > 0, "The added rule must have expressions")
				verdictExpr, ok := addRuleOp.Rule.Exprs[len(addRuleOp.Rule.Exprs)-1].(*expr.Verdict)
				require.True(t, ok, "The last expression must be a Verdict")
				assert.Equal(t, expr.VerdictDrop, verdictExpr.Kind)
			}
		})
	}
}

func TestEnqueueCreateBridgeRuleJumpOnly(t *testing.T) {
	podMac := "00:11:22:33:44:EE"
	parentChainName := IngressChain
	targetPodChainName := IngressChain + "_jumptarget"
	var hwOffset uint32 = DestinationHWOffset
	macBytes, _ := utils.ParseMAC(podMac)

	expectedExprsForJump := []expr.Any{
		&expr.Payload{OperationType: expr.PayloadLoad, DestRegister: 1, SourceRegister: 0, Base: expr.PayloadBaseLLHeader, Offset: hwOffset, Len: HWLength, CsumType: 0, CsumOffset: 0, CsumFlags: 0},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: macBytes},
		&expr.Verdict{Kind: expr.VerdictJump, Chain: targetPodChainName},
	}
	t.Logf("DEBUG_TEST_SETUP (TestEnqueueCreateBridgeRuleJumpOnly): Signature for expected jump expressions (used in mock and for comparison): %s", utils.NormalizeExprsForComparison(expectedExprsForJump))

	t.Run("RuleDoesNotExistInCache", func(t *testing.T) {
		nft := newTestNFTablesWithBaseInfra()
		nft.EnqueueCreateBridgeRuleJumpOnly(parentChainName, targetPodChainName, podMac, hwOffset)

		require.Len(t, nft.InternalQueue, 1, "Expected 1 OpAddRule operation")
		op := nft.InternalQueue[0]
		assert.Equal(t, OpAddRule, op.Type)
		require.NotNil(t, op.Rule)
		assert.Equal(t, parentChainName, op.Rule.Chain.Name)
		assert.Contains(t, op.Description, "AddRule (JumpOnly)")
		assert.Contains(t, op.Description, podMac)
		assert.Contains(t, op.Description, targetPodChainName)

		require.Len(t, op.Rule.Exprs, 3)
		assert.True(t, reflect.DeepEqual(expectedExprsForJump, op.Rule.Exprs), "Queued jump rule expressions do not match expectations.\nExpected: %#v\nActual:   %#v", expectedExprsForJump, op.Rule.Exprs)
	})

	t.Run("RuleExistsInCache", func(t *testing.T) {
		nft := newTestNFTablesWithBaseInfra()

		parentChainEntryIndex := -1
		for i := range nft.table {
			if nft.table[i].chain != nil && nft.table[i].chain.Name == parentChainName {
				parentChainEntryIndex = i
				break
			}
		}
		require.NotEqual(t, -1, parentChainEntryIndex, "Parent chain entry not found in mock table by index")
		if nft.table[parentChainEntryIndex].rules == nil {
			nft.table[parentChainEntryIndex].rules = []nftables.Rule{}
		}

		nft.table[parentChainEntryIndex].rules = append(nft.table[parentChainEntryIndex].rules, nftables.Rule{
			Table:  nft.table[parentChainEntryIndex].chain.Table,
			Chain:  nft.table[parentChainEntryIndex].chain,
			Handle: 777,
			Exprs:  expectedExprsForJump,
		})
		t.Logf("DEBUG_TEST (RuleExistsInCache): Added mock rule to nft.table[%d].rules. Its signature: %s",
			parentChainEntryIndex, utils.NormalizeExprsForComparison(nft.table[parentChainEntryIndex].rules[0].Exprs))

		nft.EnqueueCreateBridgeRuleJumpOnly(parentChainName, targetPodChainName, podMac, hwOffset)
		assert.Len(t, nft.InternalQueue, 0, "Expected 0 operations as rule should exist in cache")
	})
}
