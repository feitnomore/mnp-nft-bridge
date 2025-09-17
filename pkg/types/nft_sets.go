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
	"net"
	"strings"

	"github.com/feitnomore/mnp-nft-bridge/pkg/utils"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"k8s.io/klog/v2"
)

/* buildPortSet queues the creation or update of a set of ports.
 * It first attempts to flush the set (if it exists) and then adds the new elements.
 * If ports is empty, the set will be emptied (by FlushSet) and then AddSet will ensure it exists (empty).
 */
func (nft *NFTables) buildPortSet(chainSuffix, ruleDirection string, ruleIndex int, setType NftSetType, ports []uint16) *nftables.Set {
	tableForPortSet := nft.GetNftTableObject(TableFilter, nftables.TableFamilyBridge)
	if tableForPortSet == nil {
		klog.Errorf("[%s-buildPortSet-Enqueue] CRITICAL: Table '%s' (family bridge) not found in cache. Cannot create/update Port set.", string(setType), TableFilter)
		return nil
	}
	klog.V(7).Infof("[%s-buildPortSet-Enqueue] Using table '%s' (Family: %v) for Port set.", string(setType), tableForPortSet.Name, tableForPortSet.Family)

	deterministicSetIDStr := utils.GenerateDeterministicSetID(chainSuffix, ruleDirection, ruleIndex, string(setType))
	setName := "mnp-" + string(setType) + "-" + deterministicSetIDStr[:setSize]

	setObj := &nftables.Set{
		Anonymous: false,
		Constant:  true,
		Name:      setName,
		Table:     tableForPortSet,
		KeyType:   nftables.TypeInetService,
		ID:        0, /* The lib will find/create by name */
	}
	klog.V(5).Infof("[%s-buildPortSet-Enqueue] Preparing to update Set: Name:%s, KeyType:%v, Table:%s/%v, New elements count: %d",
		string(setType), setObj.Name, setObj.KeyType, tableForPortSet.Name, tableForPortSet.Family, len(ports))

	nft.EnqueueOperation(QueuedNftOperation{
		Type:        OpFlushSet,
		Set:         setObj,
		Description: fmt.Sprintf("FlushSet (before update/create): %s in Tbl %s/%v", setName, setObj.Table.Name, setObj.Table.Family),
	})
	klog.V(4).Infof("[%s-buildPortSet-Enqueue] Enqueued OpFlushSet for %s.", string(setType), setName)

	var setElements []nftables.SetElement
	if len(ports) > 0 {
		setElements = make([]nftables.SetElement, len(ports))
		for i, port := range ports {
			setElements[i].Key = binaryutil.BigEndian.PutUint16(port)
		}
	}

	nft.EnqueueOperation(QueuedNftOperation{
		Type:        OpAddSet,
		Set:         setObj,
		SetElements: setElements,
		Description: fmt.Sprintf("AddSet (after flush, create/populate): %s in Tbl %s/%v with %d elems", setName, setObj.Table.Name, setObj.Table.Family, len(setElements)),
	})
	klog.V(3).Infof("[%s-buildPortSet-Enqueue] Enqueued OpAddSet for %s in Tbl %s/%v with %d elems (after flush).", string(setType), setName, setObj.Table.Name, setObj.Table.Family, len(setElements))
	return setObj
}

/* buildIPSet queues the creation or update of an IP set.
 * First attempts to flush the set, then adds the new unique IPs.
 * Returns the Set object, the list of CIDRs that were not included in the set (and will require masking rules),
 * and a boolean indicating whether any valid unique IPs were found for the set.
 */
func (nft *NFTables) buildIPSet(chainSuffix, ruleDirection string, ruleIndex int, setType NftSetType, sources []string) (*nftables.Set, []string, bool) {
	deterministicSetIDStr := utils.GenerateDeterministicSetID(chainSuffix, ruleDirection, ruleIndex, string(setType))
	setName := "mnp-" + string(setType) + "-" + deterministicSetIDStr[:setSize]

	tableForIPSet := nft.GetNftTableObject(TableFilter, nftables.TableFamilyBridge)
	if tableForIPSet == nil {
		klog.Errorf("[%s-buildIPSet-Enqueue] CRITICAL: Table '%s' (family bridge) not found in cache. Cannot create/update IP set '%s'.", string(setType), TableFilter, setName)
		var allCidrs []string
		for _, src := range sources {
			ip := net.ParseIP(src)
			if ip != nil && strings.Count(src, "/") == 0 { /* If it's a single IP, add it as a /32 for consistency */
				allCidrs = append(allCidrs, src+"/32")
			} else { /* If it is already a CIDR or invalid, keep it as is */
				allCidrs = append(allCidrs, src)
			}
		}
		return nil, allCidrs, false /* No valid IP for set */
	}
	klog.V(7).Infof("[%s-buildIPSet-Enqueue] Using table '%s' (Family: %v) for IP set %s.", string(setType), tableForIPSet.Name, tableForIPSet.Family, setName)

	setObj := &nftables.Set{
		Anonymous: false,
		Constant:  true,
		Name:      setName,
		Table:     tableForIPSet,
		KeyType:   nftables.TypeIPAddr,
		ID:        0, /* The lib will find/create by name */
	}
	klog.V(5).Infof("[%s-buildIPSet-Enqueue] Preparing to update Set: Name:%s, KeyType:%v, Table:%s/%v",
		string(setType), setObj.Name, setObj.KeyType, tableForIPSet.Name, tableForIPSet.Family)

	nft.EnqueueOperation(QueuedNftOperation{
		Type:        OpFlushSet,
		Set:         setObj,
		Description: fmt.Sprintf("FlushSet (before update/create): %s in Tbl %s/%v", setName, setObj.Table.Name, setObj.Table.Family),
	})
	klog.V(4).Infof("[%s-buildIPSet-Enqueue] Enqueued OpFlushSet for %s.", string(setType), setName)

	var cidrList []string
	var setElements []nftables.SetElement
	hasValidSingleIPs := false // Novo booleano
	klog.V(7).Infof("[%s-buildIPSet-Enqueue] Processing sources for set %s: %v", string(setType), setName, sources)

	for i, cidrStr := range sources {
		klog.V(8).Infof("[%s-buildIPSet-Enqueue] Source #%d: '%s'", string(setType), i, cidrStr)
		ip, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			klog.Warningf("Failed to parse CIDR '%s' for set '%s' (type %s, ruleIdx %d, direction %s): %v. Attempting to parse as single IP.",
				cidrStr, setName, string(setType), ruleIndex, ruleDirection, err)
			singleIP := net.ParseIP(cidrStr)
			if singleIP != nil {
				ipv4Bytes := singleIP.To4()
				if ipv4Bytes != nil {
					setElements = append(setElements, nftables.SetElement{Key: ipv4Bytes})
					hasValidSingleIPs = true // Marcado como tendo IPs válidos
					klog.V(7).Infof("Added single IP '%s' to setElements for set '%s'.", cidrStr, setName)
				} else {
					klog.Warningf("Source '%s' (parsed as single IP) is not a valid IPv4 address for set '%s'. Skipping for set elements.", cidrStr, setName)
				}
			} else {
				klog.Warningf("Source '%s' is neither a valid CIDR nor a valid single IP address for set '%s'. Skipping this source entirely for nftables rules.", cidrStr, setName)
			}
			continue
		}

		ones, bits := ipNet.Mask.Size()
		isSingleIPv4 := (ip.To4() != nil && bits == 32 && ones == 32)

		switch {
		case isSingleIPv4:
			setElements = append(setElements, nftables.SetElement{Key: ip.To4()})
			hasValidSingleIPs = true /* Marked as having valid IPs */
		case ip.To4() != nil: /* It's an IPv4 range, goes to cidrList */
			cidrList = append(cidrList, cidrStr)
		default: /* It is an IPv6 CIDR (or other non-IPv4 IP type) */
			klog.Warningf("CIDR '%s' is not a standard IPv4 range/single IP for set '%s'. Adding to CIDR list for potential mask rule if applicable, or skipping.", cidrStr, setName)
			if ip.To4() == nil && strings.Contains(cidrStr, "/") { /* It's a range, but not IPv4 */
				klog.V(6).Infof("CIDR '%s' appears to be a non-IPv4 range, adding to cidrList for logging/potential future handling.", cidrStr)
				cidrList = append(cidrList, cidrStr) /* Add so that buildExpr Source Mask can turn on the warning */
			}
		}
	}
	klog.V(7).Infof("[%s-buildIPSet-Enqueue] Final setElements for %s: %d elements. HasValidSingleIPs: %t", string(setType), setName, len(setElements), hasValidSingleIPs)
	klog.V(7).Infof("[%s-buildIPSet-Enqueue] Final cidrList for %s: %v", string(setType), setName, cidrList)

	nft.EnqueueOperation(QueuedNftOperation{
		Type:        OpAddSet,
		Set:         setObj,
		SetElements: setElements,
		Description: fmt.Sprintf("AddSet (after flush, create/populate): %s in Tbl %s/%v with %d elems (CIDRs for mask: %d)", setName, setObj.Table.Name, setObj.Table.Family, len(setElements), len(cidrList)),
	})
	klog.V(3).Infof("[%s-buildIPSet-Enqueue] Enqueued OpAddSet for %s with %d elems (after flush). %d CIDRs for mask rules.", string(setType), setName, len(setElements), len(cidrList))

	return setObj, cidrList, hasValidSingleIPs
}

/* buildHWSet queues the creation or update of a set of MACs.
 * First tries to flush the set, then adds the new MACs.
 */
func (nft *NFTables) buildHWSet(chainSuffix, ruleDirection string, ruleIndex int, setType NftSetType, sources []string) *nftables.Set {
	tableForHWSet := nft.GetNftTableObject(TableFilter, nftables.TableFamilyBridge)
	if tableForHWSet == nil {
		klog.Errorf("[%s-buildHWSet-Enqueue] CRITICAL: Table '%s' (family bridge) not found in cache. Cannot create/update HW set.", string(setType), TableFilter)
		return nil
	}
	klog.V(7).Infof("[%s-buildHWSet-Enqueue] Using table '%s' (Family: %v) for HW set.", string(setType), tableForHWSet.Name, tableForHWSet.Family)

	deterministicSetIDStr := utils.GenerateDeterministicSetID(chainSuffix, ruleDirection, ruleIndex, string(setType))
	setName := "mnp-" + string(setType) + "-" + deterministicSetIDStr[:setSize]

	setObj := &nftables.Set{
		Anonymous: false,
		Constant:  true,
		Name:      setName,
		Table:     tableForHWSet,
		KeyType:   nftables.TypeEtherAddr,
		ID:        0,
	}
	klog.V(5).Infof("[%s-buildHWSet-Enqueue] Preparing to update Set: Name:%s, KeyType:%v, Table:%s/%v, New elements count: %d",
		string(setType), setObj.Name, setObj.KeyType, tableForHWSet.Name, tableForHWSet.Family, len(sources))

	nft.EnqueueOperation(QueuedNftOperation{
		Type:        OpFlushSet,
		Set:         setObj,
		Description: fmt.Sprintf("FlushSet (before update/create): %s in Tbl %s/%v", setName, setObj.Table.Name, setObj.Table.Family),
	})
	klog.V(4).Infof("[%s-buildHWSet-Enqueue] Enqueued OpFlushSet for %s.", string(setType), setName)

	var setElements []nftables.SetElement
	if len(sources) > 0 {
		for _, macStr := range sources {
			hwAddr, err := net.ParseMAC(macStr)
			if err != nil {
				klog.Warningf("[%s-buildHWSet-Enqueue] Error parsing MAC %s: %v. Skipping this source.", string(setType), macStr, err)
				continue
			}
			setElements = append(setElements, nftables.SetElement{Key: hwAddr})
		}
	}

	nft.EnqueueOperation(QueuedNftOperation{
		Type:        OpAddSet,
		Set:         setObj,
		SetElements: setElements,
		Description: fmt.Sprintf("AddSet (after flush, create/populate): %s in Tbl %s/%v with %d elems", setName, setObj.Table.Name, setObj.Table.Family, len(setElements)),
	})
	klog.V(3).Infof("[%s-buildHWSet-Enqueue] Enqueued OpAddSet for %s with %d elems (after flush).", string(setType), setName, len(setElements))
	return setObj
}

func (nft *NFTables) buildTCPPortSet(chainSuffix, ruleDirection string, ruleIndex int, ports []uint16) *nftables.Set {
	return nft.buildPortSet(chainSuffix, ruleDirection, ruleIndex, NftSetTypeTCPPort, ports)
}

func (nft *NFTables) buildUDPPortSet(chainSuffix, ruleDirection string, ruleIndex int, ports []uint16) *nftables.Set {
	return nft.buildPortSet(chainSuffix, ruleDirection, ruleIndex, NftSetTypeUDPPort, ports)
}

/* deleteNftSet queues the deletion of a set. */
func (nft *NFTables) deleteNftSet(chainSuffix, ruleDirection string, ruleIndex int, setTypeStr string) {
	deterministicSetIDStr := utils.GenerateDeterministicSetID(chainSuffix, ruleDirection, ruleIndex, setTypeStr)
	setName := "mnp-" + setTypeStr + "-" + deterministicSetIDStr[:setSize]

	tableForSetToDelete := nft.GetNftTableObject(TableFilter, nftables.TableFamilyBridge)
	if tableForSetToDelete == nil {
		klog.Errorf("[deleteNftSet-Enqueue] Could not get table object for deleting set '%s' (type %s).", setName, setTypeStr)
		return
	}

	setToDelete := &nftables.Set{
		Table: tableForSetToDelete,
		Name:  setName,
	}
	switch NftSetType(setTypeStr) {
	case NftSetTypeSrcIP, NftSetTypeDstIP:
		setToDelete.KeyType = nftables.TypeIPAddr
	case NftSetTypeSrcMAC, NftSetTypeDstMAC:
		setToDelete.KeyType = nftables.TypeEtherAddr
	case NftSetTypeTCPPort, NftSetTypeUDPPort:
		setToDelete.KeyType = nftables.TypeInetService
	default:
		klog.Errorf("[deleteNftSet-Enqueue] Unknown set type '%s' for set '%s' during KeyType assignment for deletion.", setTypeStr, setName)
		return
	}

	klog.V(5).Infof("[deleteNftSet-Enqueue] Preparing to enqueue OpDelSet for set '%s' in table %s/%v", setName, tableForSetToDelete.Name, tableForSetToDelete.Family)
	nft.EnqueueOperation(QueuedNftOperation{
		Type:        OpDelSet,
		Set:         setToDelete,
		Description: fmt.Sprintf("DelSet: %s from table %s/%v", setName, tableForSetToDelete.Name, tableForSetToDelete.Family),
	})
	klog.V(4).Infof("[deleteNftSet-Enqueue] Enqueued OpDelSet for set '%s' in table %s/%v.", setName, tableForSetToDelete.Name, tableForSetToDelete.Family)
}
