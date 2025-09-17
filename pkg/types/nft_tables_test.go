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
	"sync"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestNFTablesInstance() *NFTables {
	nft := NewNftTables()
	if nft.table == nil {
		nft.table = make([]internalTable, 0)
	}
	if nft.InternalQueue == nil {
		nft.InternalQueue = make([]QueuedNftOperation, 0)
	}
	nft.conn = nil
	nft.connLock = sync.Mutex{}
	nft.queueLock = sync.Mutex{}
	return nft
}

func TestNewNftTables(t *testing.T) {
	nft := NewNftTables()
	assert.NotNil(t, nft, "NewNftTables should return a non-nil instance")
	assert.Nil(t, nft.conn, "nft.conn should be nil initially before Init()")
}

func TestNFTablesQueueOperations(t *testing.T) {
	nft := newTestNFTablesInstance()

	assert.False(t, nft.HasPendingOperations(), "Queue should be empty initially")
	assert.Equal(t, 0, nft.PendingOperationCount(), "Pending count should be 0 initially")

	op1 := QueuedNftOperation{Type: OpAddTable, Description: "op1"}
	nft.EnqueueOperation(op1)
	assert.True(t, nft.HasPendingOperations(), "Queue should have pending operations")
	assert.Equal(t, 1, nft.PendingOperationCount(), "Pending count should be 1")

	op2 := QueuedNftOperation{Type: OpAddChain, Description: "op2"}
	nft.EnqueueOperation(op2)
	assert.Equal(t, 2, nft.PendingOperationCount(), "Pending count should be 2")

	batch := nft.DequeueOperationsBatch()
	require.NotNil(t, batch, "Dequeued batch should not be nil")
	require.Len(t, batch, 2, "Dequeued batch should have 2 operations")
	assert.Equal(t, op1.Description, batch[0].Description)
	assert.Equal(t, op2.Description, batch[1].Description)
	assert.False(t, nft.HasPendingOperations(), "Queue should be empty after dequeue")
	assert.Equal(t, 0, nft.PendingOperationCount(), "Pending count should be 0 after dequeue")

	assert.Nil(t, nft.DequeueOperationsBatch(), "Dequeue on empty queue should return nil")

	requeueBatch := []QueuedNftOperation{
		{Type: OpDelTable, Description: "requeue_op1"},
		{Type: OpDelChain, Description: "requeue_op2"},
	}
	nft.RequeueOperationsBatch(requeueBatch)
	assert.Equal(t, 2, nft.PendingOperationCount(), "Pending count should be 2 after requeue")

	dequeuedAfterRequeue := nft.DequeueOperationsBatch()
	require.Len(t, dequeuedAfterRequeue, 2)
	assert.Equal(t, "requeue_op1", dequeuedAfterRequeue[0].Description, "First requeued item not correct")
	assert.Equal(t, "requeue_op2", dequeuedAfterRequeue[1].Description, "Second requeued item not correct")
}

func TestExecuteQueuedOperationOnConnection_ErrorCases(t *testing.T) {
	nft := newTestNFTablesInstance()

	table := &nftables.Table{Name: "filter", Family: nftables.TableFamilyBridge}
	chain := &nftables.Chain{Table: table, Name: "INPUT"}

	testCases := []struct {
		name        string
		op          QueuedNftOperation
		expectError bool
	}{
		{
			name:        "OpAddTable with nil Table",
			op:          QueuedNftOperation{Type: OpAddTable, Table: nil, Description: "nil table"},
			expectError: true,
		},
		{
			name:        "OpDelTable with nil Table",
			op:          QueuedNftOperation{Type: OpDelTable, Table: nil, Description: "nil table for del"},
			expectError: true,
		},
		{
			name:        "OpAddChain with nil Chain",
			op:          QueuedNftOperation{Type: OpAddChain, Chain: nil, Description: "nil chain"},
			expectError: true,
		},
		{
			name:        "OpAddChain with nil Chain.Table",
			op:          QueuedNftOperation{Type: OpAddChain, Chain: &nftables.Chain{Name: "test"}, Description: "nil chain table"},
			expectError: true,
		},
		{
			name:        "OpFlushChain with nil Chain",
			op:          QueuedNftOperation{Type: OpFlushChain, Chain: nil, Description: "nil chain for flush"},
			expectError: true,
		},
		{
			name:        "OpDelChain with nil Chain",
			op:          QueuedNftOperation{Type: OpDelChain, Chain: nil, Description: "nil chain for del"},
			expectError: true,
		},
		{
			name:        "OpAddSet with nil Set",
			op:          QueuedNftOperation{Type: OpAddSet, Set: nil, Description: "nil set for add"},
			expectError: true,
		},
		{
			name:        "OpDelSet with nil Set",
			op:          QueuedNftOperation{Type: OpDelSet, Set: nil, Description: "nil set for del"},
			expectError: true,
		},
		{
			name:        "OpFlushSet with nil Set",
			op:          QueuedNftOperation{Type: OpFlushSet, Set: nil, Description: "nil set for flush"},
			expectError: true,
		},
		{
			name:        "OpAddRule with nil Rule",
			op:          QueuedNftOperation{Type: OpAddRule, Rule: nil, Description: "nil rule for add"},
			expectError: true,
		},
		{
			name:        "OpDelRule with nil Rule",
			op:          QueuedNftOperation{Type: OpDelRule, Rule: nil, Description: "nil rule for del"},
			expectError: true,
		},
		{
			name:        "OpDelRule without Handle",
			op:          QueuedNftOperation{Type: OpDelRule, Rule: &nftables.Rule{Table: table, Chain: chain, Handle: 0}, Description: "delete rule no handle"},
			expectError: true,
		},
		{
			name:        "Unknown Operation",
			op:          QueuedNftOperation{Type: "InvalidOpType", Description: "unknown"},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := nft.ExecuteQueuedOperationOnConnection(&tc.op)
			if tc.expectError {
				assert.Error(t, err, "Expected an error for %s", tc.name)
			} else {
				assert.NoError(t, err, "Did not expect an error for %s", tc.name)
			}
		})
	}
}

func TestFindAndGetCachedObjects(t *testing.T) {
	nft := newTestNFTablesInstance()

	tableBridge := &nftables.Table{Name: TableFilter, Family: nftables.TableFamilyBridge}
	tableInet := &nftables.Table{Name: TableFilter, Family: nftables.TableFamilyINet}

	chainIngress := &nftables.Chain{Table: tableBridge, Name: IngressChain, Type: nftables.ChainTypeFilter}
	chainEgress := &nftables.Chain{Table: tableBridge, Name: EgressChain, Type: nftables.ChainTypeFilter}
	chainPodSpecific := &nftables.Chain{Table: tableBridge, Name: IngressChain + "_pod123", Type: nftables.ChainTypeFilter}
	chainOther := &nftables.Chain{Table: tableInet, Name: "FORWARD", Type: nftables.ChainTypeFilter}

	rule1 := nftables.Rule{Table: chainIngress.Table, Chain: chainIngress, Handle: 1, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}}
	rule2 := nftables.Rule{Table: chainIngress.Table, Chain: chainIngress, Handle: 2, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}}

	nft.table = []internalTable{
		{name: tableBridge.Name, table: tableBridge, family: tableBridge.Family},
		{name: tableInet.Name, table: tableInet, family: tableInet.Family},
		{name: chainIngress.Name, chain: chainIngress, table: chainIngress.Table, family: chainIngress.Table.Family, kind: chainIngress.Type, rules: []nftables.Rule{rule1, rule2}},
		{name: chainEgress.Name, chain: chainEgress, table: chainEgress.Table, family: chainEgress.Table.Family, kind: chainEgress.Type, rules: []nftables.Rule{}},
		{name: chainPodSpecific.Name, chain: chainPodSpecific, table: chainPodSpecific.Table, family: chainPodSpecific.Table.Family, kind: chainPodSpecific.Type},
		{name: chainOther.Name, chain: chainOther, table: chainOther.Table, family: chainOther.Table.Family, kind: chainOther.Type},
	}

	t.Run("GetNftTableObject", func(t *testing.T) {
		foundTable := nft.GetNftTableObject(TableFilter, nftables.TableFamilyBridge)
		require.NotNil(t, foundTable)
		assert.Equal(t, TableFilter, foundTable.Name)
		assert.Equal(t, nftables.TableFamilyBridge, foundTable.Family)

		tempCache := nft.table
		nft.table = make([]internalTable, 0)
		newRefTable := nft.GetNftTableObject("nonexistent", nftables.TableFamilyBridge)
		require.NotNil(t, newRefTable)
		assert.Equal(t, "nonexistent", newRefTable.Name)
		nft.table = tempCache
	})

	t.Run("GetNftChainObject", func(t *testing.T) {
		foundChain := nft.GetNftChainObject(IngressChain, TableFilter, nftables.TableFamilyBridge)
		require.NotNil(t, foundChain)
		assert.Equal(t, IngressChain, foundChain.Name)
		require.NotNil(t, foundChain.Table)
		assert.Equal(t, tableBridge.Name, foundChain.Table.Name)

		notFoundChain := nft.GetNftChainObject("NONEXISTENT_CHAIN", TableFilter, nftables.TableFamilyBridge)
		require.NotNil(t, notFoundChain)
		assert.Equal(t, "NONEXISTENT_CHAIN", notFoundChain.Name)
		require.NotNil(t, notFoundChain.Table)
		assert.Equal(t, TableFilter, notFoundChain.Table.Name)
	})

	t.Run("FindBaseChain", func(t *testing.T) {
		found := nft.FindBaseChain(IngressChain, nftables.TableFamilyBridge, TableFilter)
		assert.Equal(t, chainIngress, found)
		assert.Nil(t, nft.FindBaseChain("NON_BASE_CHAIN", nftables.TableFamilyBridge, TableFilter))
	})

	t.Run("FindSpecChain", func(t *testing.T) {
		found := nft.FindSpecChain(IngressChain + "_pod123")
		assert.Equal(t, chainPodSpecific, found)

		foundBaseAsSpec := nft.FindSpecChain(IngressChain)
		assert.Equal(t, chainIngress, foundBaseAsSpec, "FindSpecChain with base chain name should find the base chain in the current cache")
	})

	t.Run("CheckChainExists", func(t *testing.T) {
		assert.True(t, nft.CheckChainExists("pod123", IngressChainType))
		assert.False(t, nft.CheckChainExists("nonexistentpod", IngressChainType))
		assert.False(t, nft.CheckChainExists("pod123", "invalidType"))
	})

	t.Run("FindChainByNameAndFamily", func(t *testing.T) {
		assert.Equal(t, chainIngress, nft.FindChainByNameAndFamily(IngressChain, nftables.TableFamilyBridge))
		assert.Equal(t, chainOther, nft.FindChainByNameAndFamily("FORWARD", nftables.TableFamilyINet))
		assert.Nil(t, nft.FindChainByNameAndFamily("NONEXISTENT", nftables.TableFamilyBridge))
	})

	t.Run("getRulesFromCachedChain", func(t *testing.T) {
		rules := nft.getRulesFromCachedChain(chainIngress)
		require.Len(t, rules, 2)
		assert.ElementsMatch(t, []nftables.Rule{rule1, rule2}, rules)

		emptyRules := nft.getRulesFromCachedChain(chainEgress)
		assert.Empty(t, emptyRules)

		nilRules := nft.getRulesFromCachedChain(&nftables.Chain{Name: "NONEXISTENT", Table: tableBridge})
		assert.Nil(t, nilRules)
	})
}

func TestNFTablesInit(t *testing.T) {
	nft := NewNftTables()

	_, connErr := nftables.New(nftables.AsLasting())
	if connErr != nil {
		t.Skipf("Skipping TestNFTablesInit: nftables.New() failed, possibly due to missing kernel support or permissions: %v", connErr)
	}

	assert.NotPanics(t, func() {
		nft.Init()
	}, "nft.Init() should not panic")
	assert.NotNil(t, nft.conn, "nft.conn should be initialized by Init()")
}

func TestEnsureBridgeInfraExistsAndFlush(t *testing.T) {
	nft := newTestNFTablesInstance()

	realConnForTest, connErr := nftables.New(nftables.AsLasting())
	if connErr != nil {
		t.Skipf("Skipping TestEnsureBridgeInfraExistsAndFlush: nftables.New() failed, cannot perform test that might interact with system: %v", connErr)
	}
	nft.conn = realConnForTest

	assert.NotPanics(t, func() {
		nft.EnsureBridgeInfraExistsAndFlush()
	}, "EnsureBridgeInfraExistsAndFlush should not panic")

	if connErr != nil {
		t.Log("Skipped cache content verification in TestEnsureBridgeInfraExistsAndFlush due to initial connection error.")
	}
	t.Log("TestEnsureBridgeInfraExistsAndFlush: Primarily a no-panic test. Detailed verification of created objects and cache state after real nftables operations requires integration testing or interface-based mocking.")
}
