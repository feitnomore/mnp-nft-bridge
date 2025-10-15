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
POD_FILE="${SCENARIO_DIR}/01_target_pod_for_delete_test.yaml"
MNP_FILE="${SCENARIO_DIR}/02_mnp_to_be_deleted.yaml"

TARGET_POD_NAME="target-pod-for-mnp-delete"
POD_NAMESPACE="default"
MNP_NAME="mnp-marked-for-deletion"
MNP_NAMESPACE="default"

POLICY_FOR_NAD_NAME="e2e-test-bridge"
POLICY_FOR_NAD_NAMESPACE_REF="default"

NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"

TARGET_POD_MAC_GLOBAL=""
EXPECTED_CHAIN_SUFFIX_GLOBAL="" # Para uso no cleanup e verificações finais

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

    # MultiNetworkPolicy may have already been deleted by the test, but we tried again to make sure.
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${POD_FILE}" # Try again if the test fails before
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"

    log_info "  Checking if the ruleset is completely clean after testing and cleanup..."
    KIND_CONTROL_PLANE_ID_CLEANUP=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
    if [[ -n "$KIND_CONTROL_PLANE_ID_CLEANUP" ]]; then
        log_info "  Waiting a little longer for the reconciler (10s)..."
        sleep 10
        FINAL_RULESET=$( ${EXEC_KIND} nft list ruleset bridge)

        ERROR_FOUND_CLEANUP=0
        # Check for absence of specific chains (rules or isolation)
        if echo "$FINAL_RULESET" | grep -qE "KUBE_MULTI_INGRESS_[0-9a-fA-F]{12}"; then
            log_error "❌ CLEANUP ERROR: Pod-specific KUBE_MULTI_INGRESS chain still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -qE "KUBE_MULTI_EGRESS_[0-9a-fA-F]{12}"; then
            log_error "❌ CLEANUP ERROR: Pod-specific KUBE_MULTI_EGRESS chain still exists!"
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
            echo "--- Final Ruleset ---";
            echo "$FINAL_RULESET";
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

# 1. Initial Setup
${KUBECTL} apply -f "${NAD_FILE}"
${KUBECTL} apply -f "${POD_FILE}"
log_info "⏳ Waiting for pod ${TARGET_POD_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${POD_NAMESPACE}" --timeout=240s
TARGET_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${POD_NAMESPACE}")
if [[ -z "$TARGET_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${TARGET_POD_NAME} not found."
    exit 1
fi

sleep 15s
log_info "🔩 Applying Initial MultiNetworkPolicy: ${MNP_FILE}"
${KUBECTL} apply -f "${MNP_FILE}"
log_info "⏳ Waiting for controller to process Initial MultiNetworkPolicy (30 seconds)..."
sleep 30

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Could not get Kind's control-plane ID."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${POD_NAMESPACE}" "${TARGET_POD_NAME}")
EXPECTED_INGRESS_CHAIN_NAME="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"
EXPECTED_EGRESS_CHAIN_NAME="KUBE_MULTI_EGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"

log_info "🔎 === Checking Initial State (Applied MultiNetworkPolicy) ==="
# Ingress Verification
log_info "🔎 [Initial] Checking JUMP Ingress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME}..."
JUMP_RULE_INGRESS_INITIAL=$( ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME}" || echo "")
if [[ -z "$JUMP_RULE_INGRESS_INITIAL" ]]
then
    log_error "❌ [Initial] JUMP Ingress rule NOT found."
    exit 1
fi
log_success "✔️ [Initial] JUMP Ingress rule found."

# Egress Verification
log_info "🔎 [Initial] Checking JUMP Egress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_EGRESS_CHAIN_NAME}..."
JUMP_RULE_EGRESS_INITIAL=$( ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
    grep -F "ether saddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_EGRESS_CHAIN_NAME}" || echo "")
if [[ -z "$JUMP_RULE_EGRESS_INITIAL" ]]
then
    log_error "❌ [Initial] JUMP Egress rule NOT found."
    exit 1
fi
log_success "✔️ [Initial] JUMP Egress rule found."

# Check if specific chains exist
log_info "🔎 [Initial] Checking if chain ${EXPECTED_INGRESS_CHAIN_NAME} exists..."
if !  ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}" > /dev/null 2>&1; then
    log_error "❌ [Initial] Chain Ingress ${EXPECTED_INGRESS_CHAIN_NAME} NOT found."
    exit 1
fi
log_success "✔️ [Initial] Chain Ingress ${EXPECTED_INGRESS_CHAIN_NAME} found."

log_info "🔎 [Initial] Checking if the chain ${EXPECTED_EGRESS_CHAIN_NAME} exists..."
if !  ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_EGRESS_CHAIN_NAME}" > /dev/null 2>&1; then
    log_error "❌ [Initial] Egress Chain ${EXPECTED_EGRESS_CHAIN_NAME} NOT found."
    exit 1
fi
log_success "✔️ [Initial] Chain Egress ${EXPECTED_EGRESS_CHAIN_NAME} found."

# Check NftPodChainMetadataCache
CONTROLLER_POD_NAME=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME" ]]; then
    log_info "🔎 [Initial] Checking NftPodChainMetadataCache..."
    EXPECTED_CACHE_KEY_INGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"
    EXPECTED_CACHE_KEY_EGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_egress"
    LOG_SINCE_DURATION="5m"
    sleep 2 # Give time for logs to be written

    # MNP has 1 ingress rule, 1 egress rule
    # PolicyRuleCount for the ingress chain will be 1, for the egress chain it will be 1.
    # PolicyIngressRuleCount and PolicyEgressRuleCount in the metadata will both be 1.
    CACHE_LOG_INGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION} | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" | \
        grep "PolicyIngressRuleCount: 1" | grep "PolicyEgressRuleCount: 1" | \
        grep "IsIsolationChain:false" | grep "PolicyRuleCount:1" | tail -n 1 || echo "")

    if [[ -z "$CACHE_LOG_INGRESS" ]]
    then
        log_error "❌ [Initial] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} missing or incorrect."
        ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION} | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" || echo "(no log for the key)"
        exit 1
    fi
    log_success "✔️ [Initial] Cache Ingress entry found and correct."

    CACHE_LOG_EGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION} | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_EGRESS}" | \
        grep "PolicyIngressRuleCount: 1" | grep "PolicyEgressRuleCount: 1" | \
        grep "IsIsolationChain:false" | grep "PolicyRuleCount:1" | tail -n 1 || echo "")

    if [[ -z "$CACHE_LOG_EGRESS" ]]
    then
        log_error "❌ [Initial] Cache Egress entry for ${EXPECTED_CACHE_KEY_EGRESS} missing or incorrect."
        ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION} | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_EGRESS}" || echo "(no log for the key)"
        exit 1
    fi
    log_success "✔️ [Initial] Cache Egress entry found and correct."
else
    log_warn "⚠️ [Initial] Unable to verify NftPodChainMetadataCache."
fi
log_success "✔️ [Initial] Initial state with MultiNetworkPolicy applied successfully verified."

# 2. Action: Delete the MultinetworkPolicy
log_info "🔩 Deleting MultiNetworkPolicy: ${MNP_FILE}"
${KUBECTL} delete -f "${MNP_FILE}"
log_info "⏳ Waiting for controller to process MNP deletion (30 seconds)..."
sleep 30

#3. MultiNetworkPolicy Post-Deletion Verification
log_info "🔎 === Checking Status After MultiNetworkPolicy Deletion ==="

log_info "🔎 [Post-Delete] Checking for ABSENCE of JUMP Ingress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME}..."
JUMP_RULE_INGRESS_POST=$( ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME}" || echo "NOT_FOUND")
if [[ "$JUMP_RULE_INGRESS_POST" != "NOT_FOUND" ]]
then
    log_error "❌ [Post-Delete] JUMP Ingress Rule STILL EXISTS, but it shouldn't."
    exit 1
fi
log_success "✔️ [Post-Delete] JUMP Ingress rule not found as expected."

log_info "🔎 [Post-Delete] Checking for ABSENCE of JUMP Egress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_EGRESS_CHAIN_NAME}..."
JUMP_RULE_EGRESS_POST=$( ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
    grep -F "ether saddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_EGRESS_CHAIN_NAME}" || echo "NOT_FOUND")
if [[ "$JUMP_RULE_EGRESS_POST" != "NOT_FOUND" ]]
then
    log_error "❌ [Post-Delete] JUMP Egress Rule STILL EXISTS, but it shouldn't."
    exit 1
fi
log_success "✔️ [Post-Delete] JUMP Egress rule not found as expected."

log_info "🔎 [Post-Delete] Checking if chain ${EXPECTED_INGRESS_CHAIN_NAME} NO LONGER EXISTS..."
if  ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}" > /dev/null 2>&1; then
    log_error "❌ [Post-Delete] Chain Ingress ${EXPECTED_INGRESS_CHAIN_NAME} STILL EXISTS."
    exit 1
fi
log_success "✔️ [Post-Delete] Chain Ingress ${EXPECTED_INGRESS_CHAIN_NAME} not found as expected."

log_info "🔎 [Post-Delete] Checking if chain ${EXPECTED_EGRESS_CHAIN_NAME} NO LONGER EXISTS..."
if  ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_EGRESS_CHAIN_NAME}" > /dev/null 2>&1; then
    log_error "❌ [Post-Delete] Egress Chain ${EXPECTED_EGRESS_CHAIN_NAME} STILL EXISTS."
    exit 1
fi
log_success "✔️ [Post-Delete] Egress Chain ${EXPECTED_EGRESS_CHAIN_NAME} not found as expected."

log_info "🔎 [Post-Delete] Checking if 'mnp-' sets were removed..."
# Run the command and redirect stderr to stdout to capture everything.
# Use || true to ensure the script doesn't exit if the command fails (e.g., no set exists).
SETS_OUTPUT_POST_DELETE=$( ${EXEC_KIND} nft list sets bridge filter 2>&1 || true)

# Now, check the output. If the command failed with "No such file or directory," it's OK.
# If it succeeded but the output contains "mnp-," it's an error.
if echo "$SETS_OUTPUT_POST_DELETE" | grep -q "mnp-"
then
    log_error "❌ [Post-Delete] 'mnp-' sets STILL EXIST:"
    echo "$SETS_OUTPUT_POST_DELETE" | grep "mnp-"
    exit 1
elif echo "$SETS_OUTPUT_POST_DELETE" | grep -i -q "Error: No such file or directory"
then
    log_success "✔️ [Post-Delete] No sets found in table (received 'No such file or directory'), as expected."
elif [[ -z "$SETS_OUTPUT_POST_DELETE" ]]
then
    log_success "✔️ [Post-Delete] No set 'mnp-' found (empty output), as expected."
else
    # The command succeeded but did not find "mnp-", which is also correct.
    log_success "✔️ [Post-Delete] No 'mnp-' set found, as expected."
fi

if [[ -n "$CONTROLLER_POD_NAME" ]]; then
    log_info "🔎 [Post-Delete] Checking if metadata for ${EXPECTED_CHAIN_SUFFIX_GLOBAL} has been removed from cache..."
    LOG_SINCE_DURATION_POST_DELETE="2m"
    sleep 2 # Log window after MNP deletion

    DELETED_LOG_INGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION_POST_DELETE} | \
        grep "nftPodChainMetadataCache" | grep "Deleted metadata" | grep "for key: ${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress" | tail -n 1 || echo "NO_INGRESS_DELETE_LOG")
    DELETED_LOG_EGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION_POST_DELETE} | \
        grep "nftPodChainMetadataCache" | grep "Deleted metadata" | grep "for key: ${EXPECTED_CHAIN_SUFFIX_GLOBAL}_egress" | tail -n 1 || echo "NO_EGRESS_DELETE_LOG")

    if [[ "$DELETED_LOG_INGRESS" == "NO_INGRESS_DELETE_LOG" ]]; then
        log_error "❌ [Post-Delete] Delete log for Ingress metadata (key ${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress) NOT found."
        exit 1
    fi
    log_success "✔️ [Post-Delete] Deletion log for Ingress metadata found."

    if [[ "$DELETED_LOG_EGRESS" == "NO_EGRESS_DELETE_LOG" ]]; then
        log_error "❌ [Post-Delete] Delete log for Egress metadata (key ${EXPECTED_CHAIN_SUFFIX_GLOBAL}_egress) NOT found."
        exit 1
    fi
    log_success "✔️ [Post-Delete] Deletion log for Egress metadata found."
else
    log_warn "⚠️ [Post-Delete] Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
