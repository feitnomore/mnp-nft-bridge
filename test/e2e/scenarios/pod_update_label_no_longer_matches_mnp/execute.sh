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
MNP_FILE="${SCENARIO_DIR}/01_mnp_targets_app_foo.yaml"
POD_INITIAL_FILE="${SCENARIO_DIR}/02_pod_initial_label_foo.yaml"
POD_UPDATED_FILE="${SCENARIO_DIR}/03_pod_updated_label_bar.yaml"

TARGET_POD_NAME="pod-for-label-change" 
POD_NAMESPACE="default" 
MNP_NAME="policy-targets-app-foo" 
MNP_NAMESPACE="default"

POLICY_FOR_NAD_NAME="e2e-test-bridge"
POLICY_FOR_NAD_NAMESPACE_REF="default"

NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"

TARGET_POD_MAC_GLOBAL=""
EXPECTED_CHAIN_SUFFIX_GLOBAL=""

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

    ${KUBECTL} delete pod "${TARGET_POD_NAME}" -n "${POD_NAMESPACE}" --ignore-not-found=true
    log_info "  Waiting for controller to process Pod deletion (15s)..."
    sleep 15
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_FILE}"
    log_info "  Waiting for controller to process MultiNetworkPolicy deletion (15s)..."
    sleep 15
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"
    
    log_info "  Checking if ruleset is clean after cleanup..."
    KIND_CONTROL_PLANE_ID_CLEANUP=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
    if [[ -n "$KIND_CONTROL_PLANE_ID_CLEANUP" ]]; then
        log_info "  Waiting a little longer for the reconciler (10s)..."
        sleep 10
        FINAL_RULESET=$(${EXEC_KIND} nft list ruleset bridge)
        
        ERROR_FOUND_CLEANUP=0
        if echo "$FINAL_RULESET" | grep -qE "KUBE_MULTI_(INGRESS|EGRESS)_[0-9a-fA-F]{12}"; then
            log_error "❌ CLEANUP ERROR: Pod-specific KUBE_MULTI chain still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -q "set mnp-"; then
            log_error "❌ CLEANUP ERROR: 'mnp-' sets still exist!"
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
    local mnp_name_param="$1"
    local mnp_ns_param="$2"
    local pod_ns_param="$3"
    local pod_name_param="$4"
    local input_str="${mnp_ns_param}/${mnp_name_param}:${pod_ns_param}/${pod_name_param}"
    echo -n "$input_str" | sha256sum | head -c 12
}

TEST_NAME=$(cat "${SCENARIO_DIR}/test.def")

log_info "🚀 Starting E2E Test: ${TEST_NAME}"

# 1. Initial Setup: Apply NAD, MultiNetworkPolicy (for app=foo), and Pod with label app=foo
${KUBECTL} apply -f "${NAD_FILE}"
log_info "🔩 Applying Multi Network Policy (select app=photo): ${MNP_FILE}"
${KUBECTL} apply -f "${MNP_FILE}"
log_info "🔩 Applying Initial Pod (label app=foo): ${POD_INITIAL_FILE}"
${KUBECTL} apply -f "${POD_INITIAL_FILE}"

log_info "⏳ Waiting for pod ${TARGET_POD_NAME} to be ready with initial label..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${POD_NAMESPACE}" --timeout=240s
TARGET_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${POD_NAMESPACE}")
if [[ -z "$TARGET_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${TARGET_POD_NAME} not found."
    exit 1
fi

log_info "⏳ Waiting for controller to process initial state (30 seconds)..."
sleep 30 

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Could not get Kind's control-plane ID."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${POD_NAMESPACE}" "${TARGET_POD_NAME}")
EXPECTED_INGRESS_CHAIN_NAME_INITIAL="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"
EXPECTED_EGRESS_CHAIN_NAME_INITIAL="KUBE_MULTI_EGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}" # MultiNetworkPolicy has Ingress and Egress

log_info "🔎 === Checking Initial State (Pod matches MultiNetworkPolicy) ==="

log_info "🔎 [Initial] Checking JUMP Ingress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL}..."
JUMP_RULE_INGRESS_INITIAL=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL}" || echo "")
if [[ -z "$JUMP_RULE_INGRESS_INITIAL" ]]
then
    log_error "❌ [Initial] JUMP Ingress rule NOT found."
    exit 1
fi
log_success "✔️ [Initial] JUMP Ingress rule found."

log_info "🔎 [Initial] Checking JUMP Egress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_EGRESS_CHAIN_NAME_INITIAL}..."
JUMP_RULE_EGRESS_INITIAL=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
    grep -F "ether saddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_EGRESS_CHAIN_NAME_INITIAL}" || echo "")
if [[ -z "$JUMP_RULE_EGRESS_INITIAL" ]]
then
    log_error "❌ [Initial] JUMP Egress rule NOT found."
    exit 1
fi
log_success "✔️ [Initial] JUMP Egress rule found."

# Check NftPodChainMetadataCache
CONTROLLER_POD_NAME=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME" ]]
then
    log_info "🔎 [Initial] Verificando NftPodChainMetadataCache..."
    ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress" | \
        grep "PolicyIngressRuleCount: 1" | grep "IsIsolationChain:false" || { log_error "❌ [Initial] Cache Ingress entry not found/incorrect."; exit 1; }
    log_success "✔️ [Initial] Cache Ingress entry found."
    ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CHAIN_SUFFIX_GLOBAL}_egress" | \
        grep "PolicyEgressRuleCount: 1" | grep "IsIsolationChain:false" || { log_error "❌ [Initial] Cache Egress entry not found/incorrect."; exit 1; }
    log_success "✔️ [Initial] Cache Egress entry found."
else
    log_warn "⚠️ [Initial] Unable to verify NftPodChainMetadataCache."
fi
log_success "✔️ [Initial] Initial state with MultiNetworkPolicy applied to the selected Pod successfully."


# 2. Action: Update Pod label to app=bar (NOT matches MultiNetworkPolicy anymore)
log_info "🔩 Updating Pod label to app=bar:${POD_UPDATED_FILE}"
${KUBECTL} apply -f "${POD_UPDATED_FILE}"
log_info "⏳ Waiting for controller to process Pod update and remove MultiNetworkPolicy rules (30 seconds)..."
sleep 30

# 3. Post-Update Label Checks
log_info "🔎 === Checking Status After Label Update (Pod NO LONGER matches MultiNetworkPolicy) ==="

log_info "🔎 [Post-Update] Checking for ABSENCE of JUMP Ingress for MAC ${TARGET_POD_MAC_GLOBAL} to ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL}..."
JUMP_RULE_INGRESS_UPDATED=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL}" || echo "NOT_FOUND")
if [[ "$JUMP_RULE_INGRESS_UPDATED" != "NOT_FOUND" ]]
then
    log_error "❌ [Post-Update] JUMP Ingress rule STILL EXISTS for ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL}, but it shouldn't."
    echo "Rule found: $JUMP_RULE_INGRESS_UPDATED"
    exit 1
fi
log_success "✔️ [Post-Update] No JUMP Ingress rule for ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL} found, as expected."

log_info "🔎 [Post-Update] Checking for ABSENCE of JUMP Egress for MAC ${TARGET_POD_MAC_GLOBAL} to ${EXPECTED_EGRESS_CHAIN_NAME_INITIAL}..."
JUMP_RULE_EGRESS_UPDATED=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
    grep -F "ether saddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_EGRESS_CHAIN_NAME_INITIAL}" || echo "NOT_FOUND")
if [[ "$JUMP_RULE_EGRESS_UPDATED" != "NOT_FOUND" ]]
then
    log_error "❌ [Post-Update] JUMP Egress rule STILL EXISTS for ${EXPECTED_EGRESS_CHAIN_NAME_INITIAL}, but it shouldn't."
    echo "Rule found: $JUMP_RULE_EGRESS_UPDATED"
    exit 1
fi
log_success "✔️ [Post-Update]No JUMP Egress rule for ${EXPECTED_EGRESS_CHAIN_NAME_INITIAL} found, as expected."

log_info "🔎 [Post-Update] Checking if chain ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL} NO LONGER exists..."
if ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME_INITIAL}" > /dev/null 2>&1; then
    log_error "❌ [Post-Update] Chain Ingress ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL} STILL EXISTS."
    exit 1
fi
log_success "✔️ [Post-Update] Chain Ingress ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL} not found as expected."

log_info "🔎 [Post-Update] Checking if chain ${EXPECTED_EGRESS_CHAIN_NAME_INITIAL} NO LONGER exists..."
if ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_EGRESS_CHAIN_NAME_INITIAL}" > /dev/null 2>&1; then
    log_error "❌ [Post-Update] Chain Egress ${EXPECTED_EGRESS_CHAIN_NAME_INITIAL} STILL EXISTS."
    exit 1
fi
log_success "✔️ [Post-Update] Egress chain ${EXPECTED_EGRESS_CHAIN_NAME_INITIAL} not found as expected."

log_info "🔎 [Post-Update] Checking if 'mnp-' sets related to these chains have been removed..."
# This check is a bit more difficult, since the set names are deterministic but based on the ruleIndex.
# A simpler check is that there should be no mnp- sets with $EXPECTED_CHAIN_SUFFIX_GLOBAL in the name.
# Or, if the ruleset is completely free of mnp- sets, even better.
SETS_REMAINING=$(${EXEC_KIND} nft list sets bridge filter 2>/dev/null | grep "mnp-" | grep "${EXPECTED_CHAIN_SUFFIX_GLOBAL}" || echo "NO_RELATED_MNP_SETS")
if [[ "$SETS_REMAINING" != "NO_RELATED_MNP_SETS" ]]
then
    log_error "❌ [Post-Update] 'mnp-' sets related to suffix ${EXPECTED_CHAIN_SUFFIX_GLOBAL} STILL EXIST:"
    echo "$SETS_REMAINING"
    exit 1
fi
log_success "✔️ [Post-Update] No 'mnp-' set related to suffix ${EXPECTED_CHAIN_SUFFIX_GLOBAL} found, as expected."


if [[ -n "$CONTROLLER_POD_NAME" ]]
then
    log_info "🔎 [Post-Update] Checking if metadata for ${EXPECTED_CHAIN_SUFFIX_GLOBAL} has been removed from cache..."
    DELETED_LOG_INGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "Deleted metadata" | grep "for key: ${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress" || echo "NO_INGRESS_DELETE_LOG")
    DELETED_LOG_EGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "Deleted metadata" | grep "for key: ${EXPECTED_CHAIN_SUFFIX_GLOBAL}_egress" || echo "NO_EGRESS_DELETE_LOG")

    if [[ "$DELETED_LOG_INGRESS" == "NO_INGRESS_DELETE_LOG" ]]
    then
        log_error "❌ [Post-Update] Deletion log for Ingress metadata (key ${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress) NOT found."
        exit 1
    fi
    log_success "✔️ [Post-Update] Deletion log for Ingress metadata found."

    if [[ "$DELETED_LOG_EGRESS" == "NO_EGRESS_DELETE_LOG" ]]
    then
        log_error "❌ [Post-Update] Deletion log for Egress metadata (key ${EXPECTED_CHAIN_SUFFIX_GLOBAL}_egress) NOT found."
        exit 1
    fi
    log_success "✔️ [Post-Update] Deletion log for Egress metadata found."
else
    log_warn "⚠️ [Post-Update] Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
