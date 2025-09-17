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
	"sync"
	"time"

	"github.com/feitnomore/mnp-nft-bridge/pkg/utils"
	"github.com/google/nftables"
	"k8s.io/klog/v2"
)

type internalTable struct {
	name   string
	chain  *nftables.Chain
	table  *nftables.Table
	family nftables.TableFamily
	kind   nftables.ChainType
	rules  []nftables.Rule
}

type NFTables struct {
	table         []internalTable
	InternalQueue []QueuedNftOperation
	conn          *nftables.Conn
	connLock      sync.Mutex
	queueLock     sync.Mutex
}

func NewNftTables() *NFTables {
	return &NFTables{}
}

func (nft *NFTables) LockConnection() {
	klog.V(7).Info("Attempting to acquire NFTables connection lock...")
	nft.connLock.Lock()
	klog.V(6).Info("NFTables connection lock acquired.")
}

func (nft *NFTables) UnlockConnection() {
	nft.connLock.Unlock()
	klog.V(6).Info("NFTables connection lock released.")
}

func (nft *NFTables) Init() {
	nftconn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		klog.Fatalf("nftables.New() failed: %v \n", err)
	}
	nft.conn = nftconn
}

func (nft *NFTables) Conn() *nftables.Conn {
	return nft.conn
}

func (nft *NFTables) flushInitialSetupWithRetry(loadID string, operationDescription string) error {
	maxBatchRetries := 5
	batchRetryDelay := 300 * time.Millisecond
	var lastBatchFlushErr error

	logEntryPrefix := fmt.Sprintf("[LoadEverything, ID: %s, OpDesc: %s]", loadID, operationDescription)

	for attempt := 1; attempt <= maxBatchRetries; attempt++ {
		klog.V(3).Infof("%s Attempting to flush (Attempt %d/%d).", logEntryPrefix, attempt, maxBatchRetries)
		flushStartTime := time.Now()
		lastBatchFlushErr = nft.conn.Flush()
		flushDuration := time.Since(flushStartTime)

		if lastBatchFlushErr == nil {
			klog.V(2).Infof("%s Initial setup operations for '%s' flushed successfully (Attempt %d, Duration: %s).", logEntryPrefix, operationDescription, attempt, flushDuration)
			return nil
		}

		klog.Errorf("%s Flush FAILED for '%s' (Attempt %d/%d, Duration: %s): %v.", logEntryPrefix, operationDescription, attempt, maxBatchRetries, flushDuration, lastBatchFlushErr)

		isRetryableError := utils.IsNftDeviceOrResourceBusyError(lastBatchFlushErr) ||
			utils.IsNftNoSuchFileError(lastBatchFlushErr) ||
			utils.IsNftSetExistsError(lastBatchFlushErr)

		if attempt < maxBatchRetries && isRetryableError {
			klog.Warningf("%s Retrying initial flush for '%s' due to '%v' in %v...", logEntryPrefix, operationDescription, lastBatchFlushErr, batchRetryDelay)
			time.Sleep(batchRetryDelay)
			batchRetryDelay *= 2
			continue
		}
		klog.Errorf("%s Unrecoverable initial flush error for '%s' or max retries (%d/%d) reached. Last error: %v.", logEntryPrefix, operationDescription, attempt, maxBatchRetries, lastBatchFlushErr)
		return lastBatchFlushErr
	}
	return lastBatchFlushErr
}

func (nft *NFTables) internalCleanOurChainsByFamily(loadID, targetFamilyStr string) error {
	klog.V(4).Infof("[LoadEverything, ID: %s, CleanChains] Listing all chains to find chains for family %s to clean.", loadID, targetFamilyStr)

	var targetFamilyValue nftables.TableFamily
	switch targetFamilyStr {
	case "TableFamilyBridge":
		targetFamilyValue = nftables.TableFamilyBridge
	case "TableFamilyINet":
		targetFamilyValue = nftables.TableFamilyINet
	default:
		return fmt.Errorf("unknown table family string for cleaning: %s", targetFamilyStr)
	}

	chains, err := nft.conn.ListChains()
	if err != nil {
		klog.Errorf("[LoadEverything, ID: %s, CleanChains] nft.conn.ListChains() failed: %v", loadID, err)
		return err
	}

	cleanedSomething := false
	for _, ch := range chains {
		if ch.Table != nil && ch.Table.Name == TableFilter && ch.Table.Family == targetFamilyValue {
			klog.V(8).Infof("[LoadEverything, ID: %s, CleanChains] Checking chain %s in table %s (family %s)", loadID, ch.Name, ch.Table.Name, utils.DecodeTableFamily(ch.Table.Family))
			if utils.CheckChain(ch.Name) {
				klog.V(5).Infof("[LoadEverything, ID: %s, CleanChains] Adding FlushChain and DelChain for managed chain %s to conn batch.", loadID, ch.Name)
				nft.conn.FlushChain(ch)
				nft.conn.DelChain(ch)
				cleanedSomething = true
			}
		}
	}
	if cleanedSomething {
		klog.V(3).Infof("[LoadEverything, ID: %s, CleanChains] Operations to clean managed chains for family %s added to conn batch.", loadID, utils.DecodeTableFamily(targetFamilyValue))
	} else {
		klog.V(4).Infof("[LoadEverything, ID: %s, CleanChains] No managed chains found to clean for family %s.", loadID, utils.DecodeTableFamily(targetFamilyValue))
	}
	return nil
}

func (nft *NFTables) internalEnsureTablesAndChainsBridge(loadID string) {
	klog.V(2).Infof("[LoadEverything, ID: %s, EnsureBridge] Ensuring 'bridge' family table '%s' and base chains (operations added to conn batch).", loadID, TableFilter)

	bridgeFilterTable := &nftables.Table{
		Family: nftables.TableFamilyBridge,
		Name:   TableFilter,
	}

	policyAccept := nftables.ChainPolicyAccept
	basePriorityValue := *nftables.ChainPriorityFilter

	ingressPriorityValue := basePriorityValue
	egressPriorityValue := basePriorityValue + 10

	pIngress := ingressPriorityValue
	pEgress := egressPriorityValue

	ingressChain := &nftables.Chain{
		Name:     IngressChain,
		Table:    bridgeFilterTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: &pIngress,
		Policy:   &policyAccept,
	}
	_ = nft.conn.AddChain(ingressChain)

	egressChain := &nftables.Chain{
		Name:     EgressChain,
		Table:    bridgeFilterTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: &pEgress,
		Policy:   &policyAccept,
	}
	_ = nft.conn.AddChain(egressChain)

	klog.V(3).Infof("[LoadEverything, ID: %s, EnsureBridge] Operations for 'bridge' family table '%s' and base chains (Ingress Prio: %d, Egress Prio: %d) added to conn batch.",
		loadID, TableFilter, ingressPriorityValue, egressPriorityValue)
}

func (nft *NFTables) LoadEverything() {
	loadID := utils.GenerateRandomShortID()
	klog.Infof("[LoadEverything, ID: %s] Starting to load and configure nftables state.", loadID)

	nft.LockConnection()
	defer nft.UnlockConnection()

	klog.V(3).Infof("[LoadEverything, ID: %s] Ensuring base table for bridge family (added to conn batch).", loadID)
	_ = nft.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyBridge,
		Name:   TableFilter,
	})
	if err := nft.flushInitialSetupWithRetry(loadID, "ensure base table"); err != nil {
		klog.Fatalf("[LoadEverything, ID: %s] nft.conn.Flush() FAILED after ensuring base table: %v. Cannot proceed.", loadID, err)
	}

	klog.V(3).Infof("[LoadEverything, ID: %s] Cleaning our pod-specific chains for TableFamilyBridge (operations will be added to conn batch).", loadID)
	if err := nft.internalCleanOurChainsByFamily(loadID, "TableFamilyBridge"); err != nil {
		klog.Errorf("[LoadEverything, ID: %s] Failed to prepare chain cleaning operations for bridge: %v. Proceeding cautiously.", loadID, err)
	}

	klog.V(3).Infof("[LoadEverything, ID: %s] Ensuring base chains for bridge family (added to conn batch).", loadID)
	nft.internalEnsureTablesAndChainsBridge(loadID)

	klog.V(2).Infof("[LoadEverything, ID: %s] Attempting to flush all setup operations (cleanup + base chains) from conn batch.", loadID)
	if err := nft.flushInitialSetupWithRetry(loadID, "main setup (cleanup + base chains)"); err != nil {
		klog.Fatalf("[LoadEverything, ID: %s] nft.conn.Flush() FAILED during main setup: %v. Cannot proceed.", loadID, err)
	}

	nft.ReloadNftTableCacheInternal()
	klog.Infof("[LoadEverything, ID: %s] Finished loading and configuring initial nftables state.", loadID)
}

func (nft *NFTables) ReloadNftTableCacheInternal() {
	klog.V(3).Info("[ReloadCacheInternal] ENTERING ReloadNftTableCacheInternal.")
	nft.table = nil

	klog.V(4).Info("[ReloadCacheInternal] About to call ListTables...")
	startTimeListTables := time.Now()
	tables, errListTables := nft.conn.ListTables()
	durationListTables := time.Since(startTimeListTables)
	klog.V(4).Infof("[ReloadCacheInternal] ListTables call finished. Took %s. Found %d tables.", durationListTables, len(tables))
	if errListTables != nil {
		klog.Errorf("[ReloadCacheInternal] nft.conn.ListTables() failed: %v. Aborting cache reload.", errListTables)
		return
	}

	allChains, errListChains := nft.conn.ListChains()
	if errListChains != nil {
		klog.Errorf("[ReloadCacheInternal] nft.conn.ListChains() failed: %v. Aborting cache reload.", errListChains)
		return
	}
	klog.V(4).Infof("[ReloadCacheInternal] ListChains successful, found %d chains across all tables. Processing...", len(allChains))

	mapChainsToTable := make(map[string][]*nftables.Chain)
	for _, ch := range allChains {
		if ch.Table != nil {
			mapKey := fmt.Sprintf("%s/%s", utils.DecodeTableFamily(ch.Table.Family), ch.Table.Name)
			mapChainsToTable[mapKey] = append(mapChainsToTable[mapKey], ch)
		}
	}

	for _, tbl := range tables {
		isRelevantTable := false
		if tbl.Family == nftables.TableFamilyBridge && tbl.Name == TableFilter {
			isRelevantTable = true
		}

		if !isRelevantTable {
			klog.V(7).Infof("[ReloadCacheInternal] Skipping table %s (Family %s) as it's not directly managed for chains/rules cache.", tbl.Name, utils.DecodeTableFamily(tbl.Family))
			continue
		}

		decodedFamily := utils.DecodeTableFamily(tbl.Family)
		klog.V(5).Infof("[ReloadCacheInternal] Processing relevant table: %s (Family %s)", tbl.Name, decodedFamily)

		tableMapKey := fmt.Sprintf("%s/%s", decodedFamily, tbl.Name)
		chainsInThisTable, ok := mapChainsToTable[tableMapKey]
		if !ok {
			klog.V(6).Infof("[ReloadCacheInternal] No chains found in map for table %s/%s.", tbl.Name, decodedFamily)
			continue
		}
		klog.V(6).Infof("[ReloadCacheInternal] Found %d chains in table %s/%s via map.", len(chainsInThisTable), tbl.Name, decodedFamily)

		for _, ch := range chainsInThisTable {
			isRelevantChain := false
			if tbl.Family == nftables.TableFamilyBridge && tbl.Name == TableFilter {
				if ch.Name == IngressChain || ch.Name == EgressChain || utils.CheckChain(ch.Name) {
					isRelevantChain = true
				}
			}

			if !isRelevantChain {
				klog.V(8).Infof("[ReloadCacheInternal] Skipping chain %s in table %s/%s as it's not a managed base or pod-specific chain.", ch.Name, tbl.Name, decodedFamily)
				continue
			}

			var myCachedTableEntry internalTable
			myCachedTableEntry.name = ch.Name
			myCachedTableEntry.chain = ch
			myCachedTableEntry.table = tbl
			myCachedTableEntry.family = tbl.Family
			myCachedTableEntry.kind = ch.Type
			myCachedTableEntry.rules = nil

			klog.V(7).Infof("[ReloadCacheInternal] Getting rules for relevant chain: %s/%s", tbl.Name, ch.Name)
			startTimeGetRules := time.Now()
			rules, errRules := nft.conn.GetRules(tbl, ch)
			durationGetRules := time.Since(startTimeGetRules)

			if errRules != nil {
				klog.Errorf("[ReloadCacheInternal] nft.conn.GetRules() for chain %s/%s failed: %v", tbl.Name, ch.Name, errRules)
			} else {
				klog.V(7).Infof("[ReloadCacheInternal] GetRules for %s/%s took %s. Found %d rules.", tbl.Name, ch.Name, durationGetRules, len(rules))
				for i := range rules {
					if rules[i] != nil {
						myCachedTableEntry.rules = append(myCachedTableEntry.rules, *rules[i])
					}
				}
			}
			nft.table = append(nft.table, myCachedTableEntry)
			logChainPrio := "N/A"
			if ch.Priority != nil {
				logChainPrio = fmt.Sprintf("%d", *ch.Priority)
			}
			klog.V(6).Infof("[ReloadCacheInternal] Cached chain: Family: %s, Table: %s, Chain: %s (Hook: %v, Prio: %s), Rules: %d",
				utils.DecodeTableFamily(myCachedTableEntry.family), myCachedTableEntry.table.Name, myCachedTableEntry.name, myCachedTableEntry.chain.Hooknum, logChainPrio, len(myCachedTableEntry.rules))
		}
	}
	klog.V(3).Info("[ReloadCacheInternal] FINISHED ReloadNftTableCacheInternal.")
}

func (nft *NFTables) ReloadNftTableCache() {
	klog.V(4).Info("ReloadNftTableCache: Public wrapper called.")
	nft.LockConnection()
	defer nft.UnlockConnection()
	nft.ReloadNftTableCacheInternal()
}

func (nft *NFTables) FindBaseChain(chainName string, family nftables.TableFamily, tableName string) *nftables.Chain {
	for i := range nft.table {
		entry := &nft.table[i]
		if entry.chain != nil && entry.chain.Name == chainName &&
			entry.family == family &&
			entry.table != nil && entry.table.Name == tableName {
			klog.V(7).Infof("FindBaseChain (from cache): Found chain %s in table %s, family %s.", chainName, tableName, utils.DecodeTableFamily(family))
			return entry.chain
		}
	}
	klog.V(6).Infof("FindBaseChain (from cache): Chain %s NOT found in table %s, family %s.", chainName, tableName, utils.DecodeTableFamily(family))
	return nil
}

func (nft *NFTables) FindSpecChain(fullChainName string) *nftables.Chain {
	for i := range nft.table {
		entry := &nft.table[i]
		if entry.chain != nil &&
			entry.chain.Name == fullChainName &&
			entry.family == nftables.TableFamilyBridge &&
			entry.table != nil && entry.table.Name == TableFilter {
			klog.V(7).Infof("FindSpecChain (from cache): Found chain %s in table %s, family bridge.", fullChainName, TableFilter)
			return entry.chain
		}
	}
	klog.V(6).Infof("FindSpecChain (from cache): Chain %s NOT found in table %s, family bridge.", fullChainName, TableFilter)
	return nil
}

func (nft *NFTables) CheckChainExists(chainSuffix string, chainType string) bool {
	var fullChainName string
	switch chainType {
	case IngressChainType:
		fullChainName = IngressChain + "_" + chainSuffix
	case EgressChainType:
		fullChainName = EgressChain + "_" + chainSuffix
	default:
		klog.Errorf("CheckChainExists: Invalid chainType: %s", chainType)
		return false
	}
	return nft.FindSpecChain(fullChainName) != nil
}

func (nft *NFTables) FindChainByNameAndFamily(chainName string, family nftables.TableFamily) *nftables.Chain {
	if (chainName == IngressChain || chainName == EgressChain) && family == nftables.TableFamilyBridge {
		return nft.FindBaseChain(chainName, family, TableFilter)
	}
	for i := range nft.table {
		entry := &nft.table[i]
		if entry.chain != nil && entry.chain.Name == chainName &&
			entry.family == family && entry.table != nil {
			klog.V(7).Infof("FindChainByNameAndFamily (from cache, generic): Found chain %s, family %s (table %s).", chainName, utils.DecodeTableFamily(family), entry.table.Name)
			return entry.chain
		}
	}
	klog.V(6).Infof("FindChainByNameAndFamily (from cache, generic): Chain %s, family %s NOT found.", chainName, utils.DecodeTableFamily(family))
	return nil
}

func (nft *NFTables) getRulesFromCachedChain(chainObj *nftables.Chain) []nftables.Rule {
	if chainObj == nil || chainObj.Table == nil {
		klog.V(8).Info("getRulesFromCachedChain: called with nil chain or chain.Table.")
		return nil
	}
	for _, cachedEntry := range nft.table {
		if cachedEntry.chain != nil && cachedEntry.chain.Table != nil &&
			cachedEntry.chain.Name == chainObj.Name &&
			cachedEntry.chain.Table.Name == chainObj.Table.Name &&
			cachedEntry.chain.Table.Family == chainObj.Table.Family {
			rulesCopy := make([]nftables.Rule, len(cachedEntry.rules))
			copy(rulesCopy, cachedEntry.rules)
			klog.V(8).Infof("getRulesFromCachedChain: Found chain %s/%s in cache, returning %d rules.", chainObj.Table.Name, chainObj.Name, len(rulesCopy))
			return rulesCopy
		}
	}
	klog.V(7).Infof("getRulesFromCachedChain: Chain %s/%s not found in cache.", chainObj.Table.Name, chainObj.Name)
	return nil
}

func (nft *NFTables) EnsureBridgeInfraExistsAndFlush() {
	nft.LockConnection()
	defer nft.UnlockConnection()

	loadID := utils.GenerateRandomShortID()
	klog.V(2).Infof("[EnsureBridgeInfraExistsAndFlush, ID: %s] Ensuring base tables and chains for bridge family (operations added to conn batch).", loadID)

	_ = nft.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyBridge,
		Name:   TableFilter,
	})
	nft.internalEnsureTablesAndChainsBridge(loadID)

	if err := nft.flushInitialSetupWithRetry(loadID, "ensure bridge infrastructure"); err != nil {
		klog.Errorf("[EnsureBridgeInfraExistsAndFlush, ID: %s] Failed to flush bridge infrastructure operations: %v. State may be inconsistent.", loadID, err)
		return
	}
	klog.V(2).Infof("[EnsureBridgeInfraExistsAndFlush, ID: %s] Successfully ensured and flushed bridge infrastructure.", loadID)
	nft.ReloadNftTableCacheInternal()
}

func (nft *NFTables) GetNftTableObject(tableName string, family nftables.TableFamily) *nftables.Table {
	for i := range nft.table {
		entry := &nft.table[i]
		if entry.table != nil && entry.table.Name == tableName && entry.table.Family == family {
			klog.V(8).Infof("[GetNftTableObject] Found table %s (family %s) in local cache nft.table.", tableName, utils.DecodeTableFamily(family))
			return entry.table
		}
	}
	klog.V(6).Infof("[GetNftTableObject] Table %s (family %s) NOT found in local cache nft.table, returning NEW reference.", tableName, utils.DecodeTableFamily(family))
	return &nftables.Table{Name: tableName, Family: family}
}

func (nft *NFTables) GetNftChainObject(chainName string, tableName string, family nftables.TableFamily) *nftables.Chain {
	for i := range nft.table {
		entry := &nft.table[i]
		if entry.chain != nil && entry.chain.Name == chainName &&
			entry.table != nil && entry.table.Name == tableName && entry.family == family {
			klog.V(8).Infof("[GetNftChainObject] Found chain %s in table %s (family %s) in local cache nft.table.", chainName, tableName, utils.DecodeTableFamily(family))
			return entry.chain
		}
	}
	klog.V(6).Infof("[GetNftChainObject] Chain %s in table %s (family %s) NOT found in local cache nft.table, returning NEW reference.", chainName, tableName, utils.DecodeTableFamily(family))
	tableObj := nft.GetNftTableObject(tableName, family)
	return &nftables.Chain{Name: chainName, Table: tableObj, Type: nftables.ChainTypeFilter}
}

func (nft *NFTables) FindSet(setName, tableName string, family nftables.TableFamily) *nftables.Set {
	nft.LockConnection()
	defer nft.UnlockConnection()

	klog.V(6).Infof("FindSet (live query): Searching for set '%s' in table '%s', family %s", setName, tableName, utils.DecodeTableFamily(family))
	tableForQuery := &nftables.Table{Name: tableName, Family: family}

	set, err := nft.conn.GetSetByName(tableForQuery, setName)
	if err != nil {
		if utils.IsNftNoSuchFileError(err) {
			klog.V(5).Infof("FindSet (live query): Set '%s' not found in table '%s' (family %s) or table does not exist: %v", setName, tableName, utils.DecodeTableFamily(family), err)
		} else {
			klog.Warningf("FindSet (live query): Error calling GetSetByName for set '%s' in table '%s' (family %s): %v", setName, tableName, utils.DecodeTableFamily(family), err)
		}
		return nil
	}

	klog.V(5).Infof("FindSet (live query): Found set '%s' (ID: %d) in table '%s', family %s.", set.Name, set.ID, tableName, utils.DecodeTableFamily(family))
	return set
}

/* EnqueueOperation adds an operation to the internal queue. */
func (nft *NFTables) EnqueueOperation(op QueuedNftOperation) {
	nft.queueLock.Lock()
	defer nft.queueLock.Unlock()
	nft.InternalQueue = append(nft.InternalQueue, op)
	klog.V(7).Infof("[NFTables.EnqueueOperation] Enqueued Op: %s - %s. Current queue size: %d", op.Type, op.Description, len(nft.InternalQueue))
}

/* HasPendingOperations checks if there are pending operations in the queue. */
func (nft *NFTables) HasPendingOperations() bool {
	nft.queueLock.Lock()
	defer nft.queueLock.Unlock()
	return len(nft.InternalQueue) > 0
}

/* PendingOperationCount returns the number of pending operations. */
func (nft *NFTables) PendingOperationCount() int {
	nft.queueLock.Lock()
	defer nft.queueLock.Unlock()
	return len(nft.InternalQueue)
}

/* DequeueOperationsBatch removes all pending operations from the queue and returns them. */
func (nft *NFTables) DequeueOperationsBatch() []QueuedNftOperation {
	nft.queueLock.Lock()
	defer nft.queueLock.Unlock()
	if len(nft.InternalQueue) == 0 {
		return nil
	}
	batch := nft.InternalQueue
	nft.InternalQueue = nil // Limpa a fila
	klog.V(5).Infof("[NFTables.DequeueOperationsBatch] Dequeued %d operations for processing.", len(batch))
	return batch
}

/* RequeueOperationsBatch adds a batch of operations back to the head of the queue. */
func (nft *NFTables) RequeueOperationsBatch(batch []QueuedNftOperation) {
	nft.queueLock.Lock()
	defer nft.queueLock.Unlock()
	if len(batch) == 0 {
		return
	}
	nft.InternalQueue = append(batch, nft.InternalQueue...) /* Add to beginning */
	klog.V(4).Infof("[NFTables.RequeueOperationsBatch] Re-queued %d operations. Total pending: %d", len(batch), len(nft.InternalQueue))
}

/* executeAddTable handles the OpAddTable operation. */
func (nft *NFTables) executeAddTable(op *QueuedNftOperation) error {
	if op.Table == nil {
		return fmt.Errorf("OpAddTable with nil Table for '%s'", op.Description)
	}
	nft.conn.AddTable(op.Table)
	klog.V(6).Infof("ExecuteQueuedOperationOnConnection: Added Table '%s' (Family: %s) to conn batch.", op.Table.Name, utils.DecodeTableFamily(op.Table.Family))
	return nil
}

/* executeDelTable handles the OpDelTable operation. */
func (nft *NFTables) executeDelTable(op *QueuedNftOperation) error {
	if op.Table == nil {
		return fmt.Errorf("OpDelTable with nil Table for '%s'", op.Description)
	}
	nft.conn.DelTable(op.Table)
	klog.V(6).Infof("ExecuteQueuedOperationOnConnection: Added DelTable for '%s' (Family: %s) to conn batch.", op.Table.Name, utils.DecodeTableFamily(op.Table.Family))
	return nil
}

/* executeAddChain handles the OpAddChain operation. */
func (nft *NFTables) executeAddChain(op *QueuedNftOperation) error {
	if op.Chain == nil || op.Chain.Table == nil {
		return fmt.Errorf("OpAddChain with nil Chain or Chain.Table for '%s'", op.Description)
	}
	nft.conn.AddChain(op.Chain)
	klog.V(6).Infof("ExecuteQueuedOperationOnConnection: Added AddChain for '%s' (Table: %s/%s) to conn batch.", op.Chain.Name, op.Chain.Table.Name, utils.DecodeTableFamily(op.Chain.Table.Family))
	return nil
}

/* executeFlushChain handles the OpFlushChain operation. */
func (nft *NFTables) executeFlushChain(op *QueuedNftOperation) error {
	if op.Chain == nil || op.Chain.Table == nil {
		return fmt.Errorf("OpFlushChain with nil Chain or Chain.Table for '%s'", op.Description)
	}
	nft.conn.FlushChain(op.Chain)
	klog.V(6).Infof("ExecuteQueuedOperationOnConnection: Added FlushChain for '%s' (Table: %s/%s) to conn batch.", op.Chain.Name, op.Chain.Table.Name, utils.DecodeTableFamily(op.Chain.Table.Family))
	return nil
}

/* executeDelChain handles the OpDelChain operation. */
func (nft *NFTables) executeDelChain(op *QueuedNftOperation) error {
	if op.Chain == nil || op.Chain.Table == nil {
		return fmt.Errorf("OpDelChain with nil Chain or Chain.Table for '%s'", op.Description)
	}
	nft.conn.DelChain(op.Chain)
	klog.V(6).Infof("ExecuteQueuedOperationOnConnection: Added DelChain for '%s' (Table: %s/%s) to conn batch.", op.Chain.Name, op.Chain.Table.Name, utils.DecodeTableFamily(op.Chain.Table.Family))
	return nil
}

/* executeAddSet handles the OpAddSet operation. */
func (nft *NFTables) executeAddSet(op *QueuedNftOperation) error {
	if op.Set == nil || op.Set.Table == nil {
		return fmt.Errorf("OpAddSet with nil Set or Set.Table for '%s'", op.Description)
	}
	addSetErr := nft.conn.AddSet(op.Set, op.SetElements)
	if addSetErr != nil && !utils.IsNftSetExistsError(addSetErr) {
		return fmt.Errorf("nft.conn.AddSet for '%s' returned error: %w", op.Set.Name, addSetErr)
	}
	klog.V(6).Infof("ExecuteQueuedOperationOnConnection: Added AddSet for '%s' (Table: %s/%s, Elements: %d) to conn batch.", op.Set.Name, op.Set.Table.Name, utils.DecodeTableFamily(op.Set.Table.Family), len(op.SetElements))
	return nil
}

/* executeDelSet handles the OpDelSet operation. */
func (nft *NFTables) executeDelSet(op *QueuedNftOperation) error {
	if op.Set == nil || op.Set.Table == nil {
		return fmt.Errorf("OpDelSet with nil Set or Set.Table for '%s'", op.Description)
	}
	nft.conn.DelSet(op.Set)
	klog.V(6).Infof("ExecuteQueuedOperationOnConnection: Added DelSet for '%s' (Table: %s/%s) to conn batch.", op.Set.Name, op.Set.Table.Name, utils.DecodeTableFamily(op.Set.Table.Family))
	return nil
}

/* ExecuteQueuedOperationOnConnection adds an internal queue operation to the nft.conn connection batch.
 * This function assumes that the nft.connLock has already been acquired.
 */
func (nft *NFTables) ExecuteQueuedOperationOnConnection(op *QueuedNftOperation) error {
	klog.V(7).Infof("[NFTables.ExecuteQueuedOperationOnConnection] Preparing to add op to nftables.Conn batch: %s - %s", op.Type, op.Description)
	var err error

	switch op.Type {
	case OpAddTable:
		err = nft.executeAddTable(op)
	case OpDelTable:
		err = nft.executeDelTable(op)
	case OpAddChain:
		err = nft.executeAddChain(op)
	case OpFlushChain:
		err = nft.executeFlushChain(op)
	case OpDelChain:
		err = nft.executeDelChain(op)
	case OpAddSet:
		err = nft.executeAddSet(op)
	case OpDelSet:
		err = nft.executeDelSet(op)
	case OpAddRule:
		if op.Rule == nil || op.Rule.Table == nil || op.Rule.Chain == nil {
			err = fmt.Errorf("ExecuteQueuedOperationOnConnection: OpAddRule with Rule, Rule.Table or Rule.Chain nil for '%s'", op.Description)
			break
		}
		nft.conn.AddRule(op.Rule)
		klog.V(6).Infof("ExecuteQueuedOperationOnConnection: Added AddRule to chain '%s' (Table: %s/%s) to conn batch. Desc: %s", op.Rule.Chain.Name, op.Rule.Table.Name, utils.DecodeTableFamily(op.Rule.Table.Family), op.Description)

	case OpDelRule:
		if op.Rule == nil || op.Rule.Table == nil || op.Rule.Chain == nil {
			err = fmt.Errorf("ExecuteQueuedOperationOnConnection: OpDelRule with Rule, Rule.Table or Rule.Chain nil for '%s'", op.Description)
			break
		}
		if op.Rule.Handle == 0 {
			klog.Errorf("ExecuteQueuedOperationOnConnection: OpDelRule for chain '%s' (Table: %s/%s) with Handle 0. Desc: %s. Content-based deletion is not directly supported via batch in the same way as AddRule. The Handle is required", op.Rule.Chain.Name, op.Rule.Table.Name, utils.DecodeTableFamily(op.Rule.Table.Family), op.Description)
			err = fmt.Errorf("ExecuteQueuedOperationOnConnection: OpDelRule for chain '%s' (Table: %s/%s) with Handle 0. Desc: %s. Content-based deletion is not directly supported via batch in the same way as AddRule. The Handle is required", op.Rule.Chain.Name, op.Rule.Table.Name, utils.DecodeTableFamily(op.Rule.Table.Family), op.Description)
			break
		}
		delRuleErr := nft.conn.DelRule(op.Rule)
		if delRuleErr != nil {
			klog.Warningf("ExecuteQueuedOperationOnConnection: nft.conn.DelRule (Handle %d, Chain %s, Table %s/%s) returned an unexpected error during preparation: %v. Desc: %s.", op.Rule.Handle, op.Rule.Chain.Name, op.Rule.Table.Name, utils.DecodeTableFamily(op.Rule.Table.Family), delRuleErr, op.Description)
		} else {
			klog.V(6).Infof("ExecuteQueuedOperationOnConnection: Added DelRule (Handle %d) for chain '%s' (Table: %s/%s) to conn batch. Desc: %s", op.Rule.Handle, op.Rule.Chain.Name, op.Rule.Table.Name, utils.DecodeTableFamily(op.Rule.Table.Family), op.Description)
		}
	case OpFlushSet:
		if op.Set == nil || op.Set.Table == nil {
			err = fmt.Errorf("ExecuteQueuedOperationOnConnection: OpFlushSet with Set or Set.Table nil for '%s'", op.Description)
			break
		}
		nft.conn.FlushSet(op.Set)
		klog.V(6).Infof("ExecuteQueuedOperationOnConnection: Added FlushSet for '%s' (Table: %s/%s) to conn batch.", op.Set.Name, op.Set.Table.Name, utils.DecodeTableFamily(op.Set.Table.Family))

	default:
		err = fmt.Errorf("ExecuteQueuedOperationOnConnection: Unknown NftOperationType: %s for '%s'", op.Type, op.Description)
	}

	if err != nil {
		klog.Warningf("Error during ExecuteQueuedOperationOnConnection for op %s (%s): %v", op.Type, op.Description, err)
	}
	return err
}
