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
NS_TARGET_FILE="${SCENARIO_DIR}/01_ns_target_for_ns_update_test.yaml"
TARGET_POD_FILE="${SCENARIO_DIR}/02_target_pod_in_ns_target_update.yaml"
NS_CLIENT_INITIAL_FILE="${SCENARIO_DIR}/03_ns_other_for_update_initial.yaml" # Client Namespace Initial State
CLIENT_POD_FILE="${SCENARIO_DIR}/04_other_client_pod_in_ns_other.yaml"
MNP_FILE="${SCENARIO_DIR}/05_mnp_allow_from_updated_client_ns.yaml"
NS_CLIENT_FINAL_FILE="${SCENARIO_DIR}/06_ns_other_for_update_final_state.yaml" # Client Namespace Final State (with label)

TARGET_POD_NAME="target-pod-in-ns-target-update"
TARGET_POD_NAMESPACE="ns-target-for-ns-update-test"

CLIENT_POD_NAME="other-client-pod-in-ns-other"
CLIENT_NAMESPACE_TO_UPDATE="ns-other-for-update" # Namespace that will have the label added

MNP_NAME="policy-allow-from-updated-client-ns"
MNP_NAMESPACE="ns-target-for-ns-update-test"

POLICY_FOR_NAD_NAME="e2e-test-bridge"
POLICY_FOR_NAD_NAMESPACE_REF="default"

NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"

TARGET_POD_MAC_GLOBAL=""
CLIENT_POD_MAC_GLOBAL=""
EXPECTED_CHAIN_SUFFIX_GLOBAL=""
SRC_MAC_SET_NAME_GLOBAL=""

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

    # Delete in reverse order or securely
    ${KUBECTL} delete --ignore-not-found=true -f "${NS_CLIENT_FINAL_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${CLIENT_POD_FILE}"
    # The client namespace may have already been deleted if the test failed before, so --ignore-not-found is important
    ${KUBECTL} delete ns "${CLIENT_NAMESPACE_TO_UPDATE}" --ignore-not-found=true
    
    ${KUBECTL} delete --ignore-not-found=true -f "${TARGET_POD_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NS_TARGET_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"
    
    log_info "  Waiting for controller to process deletions (20s)..."
    sleep 20

    log_info "  Checking if ruleset is clean after cleanup..."
    KIND_CONTROL_PLANE_ID_CLEANUP=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
    if [[ -n "$KIND_CONTROL_PLANE_ID_CLEANUP" ]]; then
        log_info "  Waiting a little longer for the reconciler (10s)..."
        sleep 10
        FINAL_RULESET=$(${EXEC_KIND} nft list ruleset bridge)
        
        ERROR_FOUND_CLEANUP=0
        if echo "$FINAL_RULESET" | grep -qE "KUBE_MULTI_INGRESS_[0-9a-fA-F]{12}"; then
            log_error "❌ CLEANUP ERROR: Pod-specific KUBE_MULTI_INGRESS chain still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -q "set mnp-"; then
            log_error "❌ CLEANUP ERROR: Sets 'mnp-' still exist!"
            ERROR_FOUND_CLEANUP=1
        fi
        if [[ -n "$TARGET_POD_MAC_GLOBAL" ]] && echo "$FINAL_RULESET" | grep -q "ether daddr ${TARGET_POD_MAC_GLOBAL} jump"; then
            log_error "❌ CLEANUP ERROR: JUMP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        
        if [[ "$ERROR_FOUND_CLEANUP" -eq 1 ]]
        then
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

# 1. Initial Setup
${KUBECTL} apply -f "${NAD_FILE}"
${KUBECTL} apply -f "${NS_TARGET_FILE}"
${KUBECTL} apply -f "${NS_CLIENT_INITIAL_FILE}" # Client namespace without the 'env=client-update' label
${KUBECTL} apply -f "${TARGET_POD_FILE}"
${KUBECTL} apply -f "${CLIENT_POD_FILE}" # Pod in client namespace

log_info "⏳ Waiting for pod ${TARGET_POD_NAME} in ${TARGET_POD_NAMESPACE} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${TARGET_POD_NAMESPACE}" --timeout=180s
TARGET_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${TARGET_POD_NAMESPACE}")
if [[ -z "$TARGET_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${TARGET_POD_NAME} not found."
    exit 1
fi

log_info "⏳ Waiting for pod ${CLIENT_POD_NAME} in ${CLIENT_NAMESPACE_TO_UPDATE} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${CLIENT_POD_NAME}" -n "${CLIENT_NAMESPACE_TO_UPDATE}" --timeout=180s
CLIENT_POD_MAC_GLOBAL=$(get_pod_mac "${CLIENT_POD_NAME}" "${CLIENT_NAMESPACE_TO_UPDATE}")
if [[ -z "$CLIENT_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${CLIENT_POD_NAME} not found."
    exit 1
fi

log_info "🔩 Applying MNP (with namespaceSelector env=client-update): ${MNP_FILE}"
${KUBECTL} apply -f "${MNP_FILE}"

log_info "⏳ Waiting for controller to process initial state (30 seconds)..."
sleep 30

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Could not get Kind's control-plane ID."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${TARGET_POD_NAMESPACE}" "${TARGET_POD_NAME}")
EXPECTED_INGRESS_CHAIN_NAME="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"

log_info "🔎 === Checking Initial State (Client Namespace does NOT match MultiNetworkPolicy selector) ==="
log_info "🔎 [Initial] Checking if chain ${EXPECTED_INGRESS_CHAIN_NAME} was NOT created (or is empty)..."
# The controller can create the chain and the jump, but the rule chain will be empty.
# Or it can optimize and create nothing. Let's check for the absence of ACCEPT rules.
if ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}" > /dev/null 2>&1; then
    log_info "   Chain ${EXPECTED_INGRESS_CHAIN_NAME} exists. Checking if it is empty..."
    INGRESS_POD_CHAIN_RULES_INITIAL=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}")
    INNER_CHAIN_CONTENT_INITIAL=$(echo "$INGRESS_POD_CHAIN_RULES_INITIAL" | sed -n "/chain ${EXPECTED_INGRESS_CHAIN_NAME} {/,/}/p" | sed "1d;\$d" | tr -d '[:space:]')
    if [[ -z "$INNER_CHAIN_CONTENT_INITIAL" ]]
    then
        log_success "✔️ [Initial] Chain ${EXPECTED_INGRESS_CHAIN_NAME} exists but is empty, as expected."
    else
        log_error "❌ [Initial] Chain ${EXPECTED_INGRESS_CHAIN_NAME} exists and is NOT empty."
        echo "Unexpected content: $INNER_CHAIN_CONTENT_INITIAL"
        exit 1
    fi
else
    log_success "✔️ [Initial] Chain ${EXPECTED_INGRESS_CHAIN_NAME} does not exist, as expected."
fi

# Check NftPodChainMetadataCache - should EXIST but with 0 rules
CONTROLLER_POD_NAME_INITIAL=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME_INITIAL" ]]
then
    log_info "🔎 [Initial] Checking NftPodChainMetadataCache for ${TARGET_POD_NAME} (expecting PolicyRuleCount:0)..."
    EXPECTED_CACHE_KEY_INITIAL="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"

    CACHE_LOG_INITIAL=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_INITIAL}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_INITIAL}" | \
        grep "PolicyRuleCount:0" | tail -n 1 || echo "")

    if [[ -z "$CACHE_LOG_INITIAL" ]]
    then
        log_error "❌ [Initial] Cache Ingress entry for key ${EXPECTED_CACHE_KEY_INITIAL} with PolicyRuleCount:0 was not found."
        ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_INITIAL}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INITIAL}" || echo "(no log for this key)"
        exit 1
    fi
    log_success "✔️ [Initial] NftPodChainMetadataCache entry with PolicyRuleCount:0 found, as expected."
else
    log_warn "⚠️ [Initial] Unable to verify NftPodChainMetadataCache."
fi

# 2. Action: Add the label 'env=client-update' to the Client Namespace
log_info "🔩 Adding label 'env=client-update' to Namespace ${CLIENT_NAMESPACE_TO_UPDATE} using: ${NS_CLIENT_FINAL_FILE}"
${KUBECTL} apply -f "${NS_CLIENT_FINAL_FILE}"
log_info "⏳ Waiting for controller to process Namespace update (30 seconds)..."
sleep 30

# 3. Namespace Label Post-Update Checks
log_info "🔎 === Checking Status After Client Namespace Label Update ==="
log_info "🔎 [Post-Update Namespace] Checking JUMP Ingress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME}..."
JUMP_RULE_INGRESS_UPDATED=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME}" || echo "")
if [[ -z "$JUMP_RULE_INGRESS_UPDATED" ]]
then
    log_error "❌ [Post-Update Namespace] JUMP Ingress rule NOT found."
    exit 1
fi
log_success "✔️ [Post-Update Namespace] JUMP Ingress rule found."

log_info "🔎 [Post-Update Namespace] Checking rules within chain ${EXPECTED_INGRESS_CHAIN_NAME}..."
INGRESS_POD_CHAIN_RULES_UPDATED=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}")
EXPECTED_PORT_MNP="80"

RULE_LINE_UPDATED=$(echo "$INGRESS_POD_CHAIN_RULES_UPDATED" | grep "ether saddr @mnp-src-mac-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
if [[ -z "$RULE_LINE_UPDATED" ]]
then
    log_error "❌ [Post-Update Namespace] Ingress rule (MAC Set -> TCP Port Set) not found in chain ${EXPECTED_INGRESS_CHAIN_NAME}."
    echo "$INGRESS_POD_CHAIN_RULES_UPDATED"
    exit 1
fi
SRC_MAC_SET_NAME_GLOBAL=$(echo "$RULE_LINE_UPDATED" | grep -o 'mnp-src-mac-[a-f0-9]\{16\}' | head -n1)
TCP_PORT_SET_NAME_UPDATED=$(echo "$RULE_LINE_UPDATED" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
if [[ -z "$SRC_MAC_SET_NAME_GLOBAL" || -z "$TCP_PORT_SET_NAME_UPDATED" ]]
then 
    log_error "❌ [Post-Update Namespace] Failed to extract set names from Ingress rule."
    exit 1
fi

log_info "🔎 [Post-Update Namespace] Checking contents of Source MAC Set ${SRC_MAC_SET_NAME_GLOBAL} (should contain ${CLIENT_POD_MAC_GLOBAL})..."
SET_CONTENT_UPDATED=$(${EXEC_KIND} nft list set bridge filter "${SRC_MAC_SET_NAME_GLOBAL}" 2>/dev/null || echo "SET_ERROR_UPDATED")
if [[ "$SET_CONTENT_UPDATED" == "SET_ERROR_UPDATED" ]]
then
    log_error "❌ [Post-Update Namespace] Failed to list source MAC set ${SRC_MAC_SET_NAME_GLOBAL}."
    exit 1
fi
if ! echo "$SET_CONTENT_UPDATED" | grep -qF "${CLIENT_POD_MAC_GLOBAL}"
then
    log_error "❌ [Post-Update Namespace] Set ${SRC_MAC_SET_NAME_GLOBAL} does NOT contain the Client Pod MAC (${CLIENT_POD_MAC_GLOBAL}) after NS label update."; 
    echo "Conteúdo do Set:"; echo "$SET_CONTENT_UPDATED"
    exit 1
fi
log_success "✔️ [Post-Update Namespace] Set ${SRC_MAC_SET_NAME_GLOBAL} contains the MAC of the Client Pod."

CONTROLLER_POD_NAME_UPDATED=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME_UPDATED" ]]
then
    log_info "🔎 [Post-Update] Checking NftPodChainMetadataCache for ${TARGET_POD_NAME} (expecting PolicyRuleCount:1)..."
    EXPECTED_CACHE_KEY_UPDATED="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"

    # Now that the rule is active, the PolicyRuleCount should be 1
    CACHE_LOG_UPDATED=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_UPDATED}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=2m | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_UPDATED}" | \
        grep "PolicyRuleCount:1" | tail -n 1 || echo "")

    if [[ -z "$CACHE_LOG_UPDATED" ]]
    then
        log_error "❌ [Post-Update] Cache Ingress entry for ${EXPECTED_CACHE_KEY_UPDATED} with PolicyRuleCount:1 was not found."
        ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_UPDATED}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=2m | \
            grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_UPDATED}" || echo "(no log for this key)"
        exit 1
    fi
    log_success "✔️ [Post-Update] NftPodChainMetadataCache entry updated with PolicyRuleCount:1, as expected."
else
    log_warn "⚠️ [Post-Update] Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
