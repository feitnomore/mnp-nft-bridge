#!/bin/bash

# Copyright 2025 Marcelo Parisi (github.com/feitnomore)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eo pipefail

exit_code=0
trap 'exit_code=$?; cleanup; exit $exit_code' EXIT

# Scenario Variables
export SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HACK_DIR="${SCENARIO_DIR}/../../../../hack"

NAD_FILE="${SCENARIO_DIR}/00_nad_bridge.yaml"
TARGET_POD_FILE="${SCENARIO_DIR}/01_target_pod.yaml"
PEER_POD_FILE="${SCENARIO_DIR}/02_peer_pod_for_egress.yaml" # Target pod for initial egress rule
MNP_INITIAL_FILE="${SCENARIO_DIR}/03_mnp_initial_with_egress.yaml"
MNP_UPDATED_FILE="${SCENARIO_DIR}/04_mnp_updated_no_egress.yaml"

TARGET_POD_NAME="target-pod-egress-removal"
PEER_POD_NAME="egress-destination-pod"
POD_NAMESPACE="default"

MNP_NAME="mnp-egress-removal-test" 
MNP_NAMESPACE="default"

POLICY_FOR_NAD_NAME="e2e-test-bridge"
POLICY_FOR_NAD_NAMESPACE_REF="default"

NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"

TARGET_POD_MAC_GLOBAL=""
PEER_POD_MAC_GLOBAL=""

# Source common functions and variables
source "${HACK_DIR}/kind-common.sh"
source "${HACK_DIR}/utils.sh"

if [ -z "$KUBECTL" ]; then
    KUBECTL="${HACK_DIR}/kubectl.sh"
fi

if [ -z "$EXEC_KIND" ]; then
    EXEC_KIND="${HACK_DIR}/exec-kind.sh"
fi

# --- Helper Functions ---

cleanup() {
    log_info "🧹 Starting cleanup for ${TEST_NAME} (Exit Code: $exit_code)..."
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_UPDATED_FILE}" 
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_INITIAL_FILE}" 
    log_info "  Waiting for controller to process MultiNetworkPolicy deletion (15s)..."
    sleep 15

    ${KUBECTL} delete --ignore-not-found=true -f "${TARGET_POD_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${PEER_POD_FILE}"
    log_info "  Waiting for controller to process Pods deletion (15s)..."
    sleep 15
    
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"

    log_info "  Checking if ruleset is clean after cleanup..."
    KIND_CONTROL_PLANE_ID_CLEANUP=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
    if [[ -n "$KIND_CONTROL_PLANE_ID_CLEANUP" ]]; then
        log_info "  Waiting a bit more for reconciler (10s)..."
        sleep 10
        FINAL_RULESET=$(${EXEC_KIND} nft list ruleset bridge)
        
        ORPHANED_INGRESS_CHAIN_PATTERN="KUBE_MULTI_INGRESS_[0-9a-fA-F]{12}"
        ORPHANED_EGRESS_CHAIN_PATTERN="KUBE_MULTI_EGRESS_[0-9a-fA-F]{12}" 

        ERROR_FOUND_CLEANUP=0
        if echo "$FINAL_RULESET" | grep -E "${ORPHANED_INGRESS_CHAIN_PATTERN}" | grep -v "_ISOLATION_" | grep -q .; then
            log_error "❌ CLEANUP ERROR: Pod-specific KUBE_MULTI_INGRESS (rule) chain still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -E "${ORPHANED_EGRESS_CHAIN_PATTERN}" | grep -v "_ISOLATION_" | grep -q .; then
            log_error "❌ CLEANUP ERROR: Pod-specific KUBE_MULTI_EGRESS (rule) chain still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -q "set mnp-"; then
            log_error "❌ CLEANUP ERROR: Sets 'mnp-' still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if [[ -n "$TARGET_POD_MAC_GLOBAL" ]]; then 
            if echo "$FINAL_RULESET" | grep -q "ether daddr ${TARGET_POD_MAC_GLOBAL} jump"; then
                 log_error "❌ CLEANUP ERROR: JUMP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} still exists!"
                 ERROR_FOUND_CLEANUP=1
            fi
            if echo "$FINAL_RULESET" | grep -q "ether saddr ${TARGET_POD_MAC_GLOBAL} jump"; then
                 log_error "❌ CLEANUP ERROR: JUMP Egress rule for MAC ${TARGET_POD_MAC_GLOBAL} still exists!"
                 ERROR_FOUND_CLEANUP=1
            fi
        fi
        
        if [[ "$ERROR_FOUND_CLEANUP" -eq 1 ]]; then
            echo "--- Final Ruleset ---"
            echo "$FINAL_RULESET"
            echo "---------------------"
        else
            log_success "✔️ Ruleset looks clean after ${TEST_NAME} cleanup."
        fi
    else
        log_warn "⚠️ Not able to find controller pod mnp-nft-bridge to check final ruleset."
    fi
    log_info "🧼 Finished cleanup."
}

get_pod_mac() {
    local pod_name="$1"
    local pod_ns="$2"
    local attempts=0
    local max_attempts=12
    local mac_address=""

    log_info "🔎 Trying to obtain MAC address for ${pod_ns}/${pod_name}..."
    while [[ -z "$mac_address" && "$attempts" -lt "$max_attempts" ]]; do
        mac_address=$(${KUBECTL} get pod "$pod_name" -n "$pod_ns" -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/network-status}' 2>/dev/null | \
                      jq -r --arg NAD_NAME "${POLICY_FOR_NAD_NAMESPACE_REF}/${POLICY_FOR_NAD_NAME}" '.[] | select(.name == $NAD_NAME) | .mac' 2>/dev/null || echo "")
        if [[ -z "$mac_address" ]]; then
             mac_address=$(${KUBECTL} get pod "$pod_name" -n "$pod_ns" -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/network-status}' 2>/dev/null | \
                      jq -r --arg NAD_NAME_NO_NS "${POLICY_FOR_NAD_NAME}" '.[] | select(.name == $NAD_NAME_NO_NS) | .mac' 2>/dev/null || echo "")
        fi

        if [[ -n "$mac_address" ]]; then
            log_success "✔️ MAC address for ${pod_ns}/${pod_name} is: ${mac_address}"
            echo "$mac_address"
            return 0
        fi
       attempts=$((attempts + 1))
        log_info "⏳ MAC not found (attempt ${attempts}/${max_attempts}). Waiting 5s..."
        sleep 5
    done
    log_error "❌ Failure obtaining MAC address for ${pod_ns}/${pod_name} after ${max_attempts} attempts."
    echo ""
    return 1
}

generate_pod_chain_suffix() {
    local mnp_name_param="$1"; local mnp_ns_param="$2"; local pod_ns_param="$3"; local pod_name_param="$4"
    local input_str="${mnp_ns_param}/${mnp_name_param}:${pod_ns_param}/${pod_name_param}"
    echo -n "$input_str" | sha256sum | head -c 12
}

TEST_NAME=$(cat "${SCENARIO_DIR}/test.def")

log_info "🚀 Starting E2E Test: ${TEST_NAME}"

${KUBECTL} apply -f "${NAD_FILE}"
${KUBECTL} apply -f "${TARGET_POD_FILE}"
${KUBECTL} apply -f "${PEER_POD_FILE}"

log_info "⏳ Waiting pod ${TARGET_POD_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${POD_NAMESPACE}" --timeout=240s
TARGET_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${POD_NAMESPACE}")
if [[ -z "$TARGET_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address for pod ${TARGET_POD_NAME} not found. Aborting."
    exit 1
fi

log_info "⏳ Waiting pod ${PEER_POD_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${PEER_POD_NAME}" -n "${POD_NAMESPACE}" --timeout=240s
PEER_POD_MAC_GLOBAL=$(get_pod_mac "${PEER_POD_NAME}" "${POD_NAMESPACE}") # Used to check the egress rule
if [[ -z "$PEER_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address for pod ${PEER_POD_NAME} not found. Aborting."
    exit 1
fi

sleep 15s
log_info "🔩 Applying Initial MultiNetworkPolicy (with Ingress and Egress): ${MNP_INITIAL_FILE}"
${KUBECTL} apply -f "${MNP_INITIAL_FILE}"
log_info "⏳ Waiting for controller to process Initial MultiNetworkPolicy (30 seconds)..."
sleep 30

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Failed to obtain container ID for Kind's control-plane."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${POD_NAMESPACE}" "${TARGET_POD_NAME}")
EXPECTED_INGRESS_CHAIN_NAME="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX}"
EXPECTED_EGRESS_CHAIN_NAME="KUBE_MULTI_EGRESS_${EXPECTED_CHAIN_SUFFIX}"

log_info "🔎 === Checking Initial State (MultiNetworkPolicy with Ingress and Egress) ==="
# Initial Ingress Verification
log_info "🔎 [Initial] Checking JUMP Ingress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME}..."
JUMP_RULE_INGRESS_INITIAL=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME}" || echo "")
if [[ -z "$JUMP_RULE_INGRESS_INITIAL" ]]
then
    log_error "❌ [Initial] JUMP Ingress rule NOT found."
    exit 1
fi
log_success "✔️ [Initial] JUMP Ingress rule found."

log_info "🔎 [Initial] Checking PRESENCE of DROP Ingress for MAC ${TARGET_POD_MAC_GLOBAL} in KUBE_MULTI_INGRESS..."
DROP_RULE_INGRESS_BASE_INITIAL=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} drop" || echo "NOT_FOUND")
if [[ "$DROP_RULE_INGRESS_BASE_INITIAL" == "NOT_FOUND" ]]
then
    log_error "❌ [Initial] Specific DROP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} was NOT found in KUBE_MULTI_INGRESS, but it should have been."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
    exit 1
else
    log_success "✔️ [Initial] Specific DROP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} in KUBE_MULTI_INGRESS found, as expected."
fi

# Initial Egress Verification
log_info "🔎 [Initial] Checking JUMP Egress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_EGRESS_CHAIN_NAME}..."
JUMP_RULE_EGRESS_INITIAL=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
    grep -F "ether saddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_EGRESS_CHAIN_NAME}" || echo "")
if [[ -z "$JUMP_RULE_EGRESS_INITIAL" ]]
then
    log_error "❌ [Initial] JUMP Egress rule NOT found."
    exit 1
fi
log_success "✔️ [Initial] JUMP Egress rule found."

log_info "🔎 [Initial] Checking PRESENCE of DROP Egress for MAC ${TARGET_POD_MAC_GLOBAL} in KUBE_MULTI_EGRESS..."
DROP_RULE_EGRESS_BASE_INITIAL=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
    grep -F "ether saddr ${TARGET_POD_MAC_GLOBAL} drop" || echo "NOT_FOUND")
if [[ "$DROP_RULE_EGRESS_BASE_INITIAL" == "NOT_FOUND" ]]
then
    log_error "❌ [Initial] Specific DROP Egress rule for MAC ${TARGET_POD_MAC_GLOBAL} was NOT found in KUBE_MULTI_EGRESS, but it should have been."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS;
    exit 1
else
    log_success "✔️ [Initial] Specific DROP Egress rule for MAC ${TARGET_POD_MAC_GLOBAL} in KUBE_MULTI_EGRESS found, as expected."
fi

# Check the contents of the Egress chain (for the rule with podSelector)
log_info "🔎 [Initial] Checking contents of chain ${EXPECTED_EGRESS_CHAIN_NAME}..."
EGRESS_POD_CHAIN_RULES_INITIAL=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_EGRESS_CHAIN_NAME}")
EGRESS_RULE_TO_PEER_POD=$(echo "$EGRESS_POD_CHAIN_RULES_INITIAL" | grep "ether daddr @mnp-dst-mac-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
if [[ -z "$EGRESS_RULE_TO_PEER_POD" ]]
then
    log_error "❌ [Initial] Egress rule for peer pod not found."
    echo "$EGRESS_POD_CHAIN_RULES_INITIAL"
    exit 1
fi
DST_MAC_SET_NAME_INITIAL=$(echo "$EGRESS_RULE_TO_PEER_POD" | grep -o 'mnp-dst-mac-[a-f0-9]\{16\}' | head -n1)
TCP_PORT_SET_NAME_EGRESS_INITIAL=$(echo "$EGRESS_RULE_TO_PEER_POD" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
${EXEC_KIND} nft list set bridge filter "${DST_MAC_SET_NAME_INITIAL}" | grep -qF "${PEER_POD_MAC_GLOBAL}" || \
    { log_error "❌ [Initial] Set ${DST_MAC_SET_NAME_INITIAL} does not contain peer pod MAC ${PEER_POD_MAC_GLOBAL}."; exit 1; }
${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME_EGRESS_INITIAL}" | grep -qE "(^|[[:space:],{])443([[:space:],}]|$)" || \
    { log_error "❌ [Initial] Set ${TCP_PORT_SET_NAME_EGRESS_INITIAL} does not contain port 443."; exit 1; }
log_success "✔️ [Initial] Egress rule for peer pod verified."

CONTROLLER_POD_NAME=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME" ]]
then
    log_info "🔎 [Initial] Checking NftPodChainMetadataCache..."
    EXPECTED_CACHE_KEY_INGRESS_INITIAL="${EXPECTED_CHAIN_SUFFIX}_ingress"
    EXPECTED_CACHE_KEY_EGRESS_INITIAL="${EXPECTED_CHAIN_SUFFIX}_egress"
    # MNP has 1 ingress rule, 1 egress rule
    ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS_INITIAL}" | \
        grep "PolicyIngressRuleCount: 1" | grep "IsIsolationChain:false" || { log_error "❌ [Initial] Cache Ingress entry not found/incorrect."; exit 1; }
    log_success "✔️ [Initial] Cache Ingress entry found."
    ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_EGRESS_INITIAL}" | \
        grep "PolicyEgressRuleCount: 1" | grep "IsIsolationChain:false" || { log_error "❌ [Initial] Cache Egress entry not found/incorrect."; exit 1; }
    log_success "✔️ [Initial] Cache Egress entry found."
else
    log_warn "⚠️ [Initial] Unable to verify NftPodChainMetadataCache."
fi


log_info "🔩 Applying Updated MultiNetworkPolicy (without Egress section): ${MNP_UPDATED_FILE}"
${KUBECTL} apply -f "${MNP_UPDATED_FILE}"
log_info "⏳ Waiting for controller to process MultiNetworkPolicy Updated (30 seconds)..."
sleep 30

log_info "🔎 === Checking Status After Update (MultiNetworkPolicy without Egress) ==="
# Ingress Verification (must remain)
log_info "🔎 [Updated] Checking JUMP Ingress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME}..."
JUMP_RULE_INGRESS_UPDATED=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME}" || echo "")
if [[ -z "$JUMP_RULE_INGRESS_UPDATED" ]]
then
    log_error "❌ [Updated] JUMP Ingress rule NOT found."
    exit 1
fi
log_success "✔️ [Updated] JUMP Ingress rule still exist."

# Egress verification (there should NO longer be a chain or jump to egress this MultiNetworkPolicy)
log_info "🔎 [Updated] Checking for ABSENCE of JUMP Egress for MAC ${TARGET_POD_MAC_GLOBAL} to ${EXPECTED_EGRESS_CHAIN_NAME}..."
JUMP_RULE_EGRESS_UPDATED=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
    grep -F "ether saddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_EGRESS_CHAIN_NAME}" || echo "NOT_FOUND")
if [[ "$JUMP_RULE_EGRESS_UPDATED" != "NOT_FOUND" ]]
then
    log_error "❌ [Updated] JUMP Egress rule for ${EXPECTED_EGRESS_CHAIN_NAME} WAS found, but it shouldn't have been."
    echo "Rule found: $JUMP_RULE_EGRESS_UPDATED"
    exit 1
fi
log_success "✔️ [Updated] No JUMP Egress rule for ${EXPECTED_EGRESS_CHAIN_NAME} found, as expected."

log_info "🔎 [Updated] Checking if chain ${EXPECTED_EGRESS_CHAIN_NAME} NO LONGER exists..."
if ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_EGRESS_CHAIN_NAME}" > /dev/null 2>&1; then
    log_error "❌ [Updated] Egress Chain ${EXPECTED_EGRESS_CHAIN_NAME} STILL EXISTS, but it shouldn't."
    ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_EGRESS_CHAIN_NAME}"
    exit 1
fi
log_success "✔️ [Updated] Egress chain ${EXPECTED_EGRESS_CHAIN_NAME} not found as expected."

# Verify that the Egress sets were removed
# The destination MAC set name was $DST_MAC_SET_NAME_INITIAL
# The egress TCP port set name was $TCP_PORT_SET_NAME_EGRESS_INITIAL
if [[ -n "$DST_MAC_SET_NAME_INITIAL" ]]
then
    log_info "🔎 [Updated] Checking if Egress destination MAC set ${DST_MAC_SET_NAME_INITIAL} NO LONGER exists..."
    if ${EXEC_KIND} nft list set bridge filter "${DST_MAC_SET_NAME_INITIAL}" > /dev/null 2>&1; then
        log_error "❌ [Updated] Egress Destination MAC Set ${DST_MAC_SET_NAME_INITIAL} STILL EXISTS."; exit 1
    fi
    log_success "✔️ [Updated] Egress destination MAC set ${DST_MAC_SET_NAME_INITIAL} not found as expected."
fi
if [[ -n "$TCP_PORT_SET_NAME_EGRESS_INITIAL" ]]
then
    log_info "🔎 [Updated] Checking if TCP Egress port set ${TCP_PORT_SET_NAME_EGRESS_INITIAL} NO LONGER exists..."
    if ${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME_EGRESS_INITIAL}" > /dev/null 2>&1; then
        log_error "❌ [Updated] TCP Egress Port Set ${TCP_PORT_SET_NAME_EGRESS_INITIAL} STILL EXISTS."; exit 1
    fi
    log_success "✔️ [Updated] TCP Egress port set ${TCP_PORT_SET_NAME_EGRESS_INITIAL} not found as expected."
fi


if [[ -n "$CONTROLLER_POD_NAME" ]]
then
    log_info "🔎 [Updated] Checking NftPodChainMetadataCache..."
    # The Ingress entry should remain, but the EgressRuleCount should be 0
    # The Egress entry should be removed
    EXPECTED_CACHE_KEY_INGRESS_UPDATED="${EXPECTED_CHAIN_SUFFIX}_ingress"
    EXPECTED_CACHE_KEY_EGRESS_REMOVED="${EXPECTED_CHAIN_SUFFIX}_egress"

    log_info "   Checking Ingress key: ${EXPECTED_CACHE_KEY_INGRESS_UPDATED} with PolicyIngressRuleCount:1, PolicyEgressRuleCount:0, IsIsolationChain:false"
    # Give time for the log to be written
    sleep 2 
    CACHE_LOG_INGRESS_UPDATED=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=2m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS_UPDATED}" | \
        grep "PolicyIngressRuleCount: 1" | grep "PolicyEgressRuleCount: 0" | grep "IsIsolationChain:false" | tail -n 1 || echo "")
    if [[ -z "$CACHE_LOG_INGRESS_UPDATED" ]]
    then
        log_error "❌ [Updated] Ingress Cache ${EXPECTED_CACHE_KEY_INGRESS_UPDATED} does not reflect EgressRuleCount:0 or IsIsolationChain:false."
        ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=2m | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS_UPDATED}" || echo "(no log found for the key)"
        exit 1
    fi
    log_success "✔️ [Updated] Cache Ingress entry ${EXPECTED_CACHE_KEY_INGRESS_UPDATED} updated correctly."

    log_info "   Checking if Egress key ${EXPECTED_CACHE_KEY_EGRESS_REMOVED} was removed (Deleted metadata log)..."
    DELETED_LOG_EGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "Deleted metadata" | grep "for key: ${EXPECTED_CACHE_KEY_EGRESS_REMOVED}" || echo "NO_DELETE_LOG")
    if [[ "$DELETED_LOG_EGRESS" == "NO_DELETE_LOG" ]]
    then
        # If there is no delete log, check if there are no recent Add/Update logs for it
        RECENT_ADD_UPDATE_EGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=1m | \
            grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_EGRESS_REMOVED}" || echo "NO_RECENT_ADD_UPDATE")
        if [[ "$RECENT_ADD_UPDATE_EGRESS" != "NO_RECENT_ADD_UPDATE" ]]
        then
            log_error "❌ [Updated] Egress key ${EXPECTED_CACHE_KEY_EGRESS_REMOVED} was not explicitly deleted and had recent Add/Update."
            exit 1
        fi
    fi
    log_success "✔️ [Updated] Egress key ${EXPECTED_CACHE_KEY_EGRESS_REMOVED} appears to have been removed from the cache."
else
    log_warn "⚠️ [Updated] Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
