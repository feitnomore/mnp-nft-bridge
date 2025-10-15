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
MNP_FILE="${SCENARIO_DIR}/01_mnp_for_pod_restart_test.yaml" 
POD_FILE="${SCENARIO_DIR}/02_pod_to_simulate_restart.yaml" 

TARGET_POD_NAME="pod-to-simulate-restart"
POD_NAMESPACE="default" 
MNP_NAME="policy-for-pod-restart-test" 
MNP_NAMESPACE="default"

POLICY_FOR_NAD_NAME="e2e-test-bridge"
POLICY_FOR_NAD_NAMESPACE_REF="default"

NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"

INITIAL_POD_MAC_GLOBAL=""
RESTARTED_POD_MAC_GLOBAL=""
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

    ${KUBECTL} delete --ignore-not-found=true -f "${POD_FILE}"
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
        if echo "$FINAL_RULESET" | grep -qE "KUBE_MULTI_INGRESS_[0-9a-fA-F]{12}"; then
            log_error "❌ CLEANUP ERROR: Pod-specific KUBE_MULTI_INGRESS chain still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -q "set mnp-"; then
            log_error "❌ CLEANUP ERROR:'mnp-' sets still exist!"
            ERROR_FOUND_CLEANUP=1
        fi
        # We cannot reliably verify specific MACs here since the pod has been recreated.
        
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

verify_ingress_rules_state() {
    local pod_mac_to_check="$1"
    local expected_chain_suffix_to_check="$2"
    local state_label="$3" 
    local should_exist="$4" 

    local expected_ingress_chain="KUBE_MULTI_INGRESS_${expected_chain_suffix_to_check}"

    log_info "🔎 ${state_label} Checking JUMP Ingress for MAC ${pod_mac_to_check} for ${expected_ingress_chain}..."
    JUMP_RULE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
        grep -F "ether daddr ${pod_mac_to_check} jump ${expected_ingress_chain}" || echo "NOT_FOUND")

    if [[ "$should_exist" == "true" ]]
    then
        if [[ "$JUMP_RULE_OUTPUT" == "NOT_FOUND" ]]
        then
            log_error "❌ ${state_label} JUMP Ingress rule for ${expected_ingress_chain} NOT found, but was expected."
            return 1
        fi
        log_success "✔️ ${state_label} JUMP Ingress rule for ${expected_ingress_chain} found."

        log_info "🔎 ${state_label} Checking PRESENCE of DROP Ingress for MAC ${pod_mac_to_check} in KUBE_MULTI_INGRESS..."
        DROP_RULE_BASE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
            grep -F "ether daddr ${pod_mac_to_check} drop" || echo "NOT_FOUND")
        if [[ "$DROP_RULE_BASE_OUTPUT" == "NOT_FOUND" ]]
        then
            log_error "❌ ${state_label} DROP Ingress rule for MAC ${pod_mac_to_check} was NOT found in KUBE_MULTI_INGRESS, but it should have been."
            return 1
        else
            log_success "✔️ ${state_label} MAC-specific DROP Ingress rule ${pod_mac_to_check} in KUBE_MULTI_INGRESS found, as expected."
        fi

        log_info "🔎 ${state_label} Verifying contents of chain ${expected_ingress_chain}..."
        INGRESS_POD_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${expected_ingress_chain}")
        
        EXPECTED_RULE_PATTERN_PART1="ip saddr @mnp-src-ip-"
        EXPECTED_RULE_PATTERN_PART2="tcp dport @mnp-tcp-port-"
        EXPECTED_RULE_PATTERN_PART3="accept"

        MATCHING_RULE_LINE=$(echo "$INGRESS_POD_CHAIN_RULES" | grep -F "$EXPECTED_RULE_PATTERN_PART1" | grep -F "$EXPECTED_RULE_PATTERN_PART2" | grep -F "$EXPECTED_RULE_PATTERN_PART3")

        if [[ -n "$MATCHING_RULE_LINE" ]]
        then
            log_success "✔️ ${state_label} Expected ACCEPT rule found in ${expected_ingress_chain}."
        else
            log_error "❌ ${state_label} Expected ACCEPT rule (containing '${EXPECTED_RULE_PATTERN_PART1}', '${EXPECTED_RULE_PATTERN_PART2}', and '${EXPECTED_RULE_PATTERN_PART3}') not found in ${expected_ingress_chain}."
            echo "Contents of the chain ${expected_ingress_chain}:"
            echo "$INGRESS_POD_CHAIN_RULES"
            return 1
        fi

    elif [[ "$should_exist" == "false" ]]
    then
        if [[ "$JUMP_RULE_OUTPUT" != "NOT_FOUND" ]]
        then
            log_error "❌ ${state_label} JUMP Ingress rule for MAC ${pod_mac_to_check} WAS found, but was NOT expected."
            return 1
        fi
        log_success "✔️ ${state_label} No JUMP Ingress rule for MAC ${pod_mac_to_check} found, as expected."

        log_info "🔎 ${state_label} Checking if chain ${expected_ingress_chain} NO LONGER exists..."
        if ${EXEC_KIND} nft list chain bridge filter "${expected_ingress_chain}" > /dev/null 2>&1; then
            log_error "❌ ${state_label} Chain Ingress ${expected_ingress_chain} STILL EXISTS, but it shouldn't."
            return 1
        fi
        log_success "✔️ ${state_label} Ingress chain ${expected_ingress_chain} not found as expected."
    fi
    return 0
}

TEST_NAME=$(cat "${SCENARIO_DIR}/test.def")

log_info "🚀 Starting E2E Test: ${TEST_NAME}"

${KUBECTL} apply -f "${NAD_FILE}"
${KUBECTL} apply -f "${MNP_FILE}"
${KUBECTL} apply -f "${POD_FILE}"

log_info "⏳ Waiting for pod ${TARGET_POD_NAME} to be ready (first time)..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${POD_NAMESPACE}" --timeout=240s
INITIAL_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${POD_NAMESPACE}")
if [[ -z "$INITIAL_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${TARGET_POD_NAME} (initial) not found."
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

log_info "🔎 === Checking Initial State (Pod Running, MultiNetworkPolicy Applied) ==="
verify_ingress_rules_state "${INITIAL_POD_MAC_GLOBAL}" "${EXPECTED_CHAIN_SUFFIX_GLOBAL}" "[Initial]" "true" || exit 1

CONTROLLER_POD_NAME=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME" ]]
then
    log_info "🔎 [Initial] Checking NftPodChainMetadataCache for ${TARGET_POD_NAME}..."
    EXPECTED_CACHE_KEY_INGRESS_INITIAL="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"
    
    INGRESS_CACHE_LOGS_INITIAL=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS_INITIAL}" || echo "")

    INGRESS_COUNT_MATCH_INITIAL=false
    EGRESS_COUNT_MATCH_FOR_INGRESS_KEY_INITIAL=false 
    ISOLATION_FLAG_MATCH_INITIAL=false
    POLICY_RULE_COUNT_MATCH_INITIAL=false

    if [[ -n "$INGRESS_CACHE_LOGS_INITIAL" ]]; then
        if echo "$INGRESS_CACHE_LOGS_INITIAL" | grep -q "PolicyIngressRuleCount: 1"; then
            INGRESS_COUNT_MATCH_INITIAL=true
        fi
        if echo "$INGRESS_CACHE_LOGS_INITIAL" | grep -q "PolicyEgressRuleCount: 0"; then # MultiNetworkPolicy only have Ingress
            EGRESS_COUNT_MATCH_FOR_INGRESS_KEY_INITIAL=true
        fi
        if echo "$INGRESS_CACHE_LOGS_INITIAL" | grep -q "IsIsolationChain:false"; then
            ISOLATION_FLAG_MATCH_INITIAL=true
        fi
        if echo "$INGRESS_CACHE_LOGS_INITIAL" | grep -q "PolicyRuleCount:1"; then 
            POLICY_RULE_COUNT_MATCH_INITIAL=true
        fi
    fi

    if [[ "$INGRESS_COUNT_MATCH_INITIAL" == true && \
          "$EGRESS_COUNT_MATCH_FOR_INGRESS_KEY_INITIAL" == true && \
          "$ISOLATION_FLAG_MATCH_INITIAL" == true && \
          "$POLICY_RULE_COUNT_MATCH_INITIAL" == true ]]; then
        log_success "✔️ [Initial] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS_INITIAL} found and correct."
    else
        log_error "❌ [Initial] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS_INITIAL} missing or incorrect."
        log_info "   Logs found for key ${EXPECTED_CACHE_KEY_INGRESS_INITIAL} (last lines):"
        echo "$INGRESS_CACHE_LOGS_INITIAL" | tail -n 5
        log_info "   Checked: PolicyIngressRuleCount:1 ($INGRESS_COUNT_MATCH_INITIAL), PolicyEgressRuleCount:0 ($EGRESS_COUNT_MATCH_FOR_INGRESS_KEY_INITIAL), IsIsolationChain:false ($ISOLATION_FLAG_MATCH_INITIAL), PolicyRuleCount:1 ($POLICY_RULE_COUNT_MATCH_INITIAL)"
        exit 1
    fi
else
    log_warn "⚠️ [Initial] Unable to verify NftPodChainMetadataCache."
fi
log_success "✔️ [Initial] Initial state verified successfully."

log_info "🔩 Deleting Pod ${TARGET_POD_NAME} to simulate restart..."
${KUBECTL} delete pod "${TARGET_POD_NAME}" -n "${POD_NAMESPACE}" --grace-period=0 --force || log_warn "Failed to delete pod (may be already gone)."
log_info "⏳ Waiting for controller to process Pod deletion (30 seconds)..."
sleep 30 

log_info "🔎 === Checking Intermediate State (Pod Deleted, MultiNetworkPolicy Still Exists) ==="
verify_ingress_rules_state "${INITIAL_POD_MAC_GLOBAL}" "${EXPECTED_CHAIN_SUFFIX_GLOBAL}" "[Intermediate-Pod Deleted]" "false" || exit 1
if [[ -n "$CONTROLLER_POD_NAME" ]]
then
    log_info "🔎 [Intermediate] Checking if metadata for ${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress has been removed from cache..."
    DELETED_LOG_INGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=2m | \
        grep "nftPodChainMetadataCache" | grep "Deleted metadata" | grep "for key: ${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress" | tail -n 1 || echo "NO_DELETE_LOG")
    if [[ "$DELETED_LOG_INGRESS" == "NO_DELETE_LOG" ]]
    then
        log_error "❌ [Intermediate] Deletion log for Ingress metadata NOT found."
        exit 1
    fi
    log_success "✔️ [Intermediate] Deletion log for Ingress metadata found."
else
    log_warn "⚠️ [Intermediate] Unable to verify NftPodChainMetadataCache."
fi
log_success "✔️ [Intermediate] Status after pod deletion verified successfully."


log_info "🔩 Recreating Pod ${TARGET_POD_NAME}..."
${KUBECTL} apply -f "${POD_FILE}"
log_info "⏳ Waiting for pod ${TARGET_POD_NAME} to be ready (after restart)..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${POD_NAMESPACE}" --timeout=180s
RESTARTED_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${POD_NAMESPACE}")
if [[ -z "$RESTARTED_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${TARGET_POD_NAME} (post-restart) not found."
    exit 1
fi

if [[ "$INITIAL_POD_MAC_GLOBAL" != "$RESTARTED_POD_MAC_GLOBAL" ]]
then
    log_warn "⚠️ Pod's MAC address changed after restart. Initial: ${INITIAL_POD_MAC_GLOBAL}, Restarted: ${RESTARTED_POD_MAC_GLOBAL}. The test will proceed with the new MAC."
fi

log_info "⏳ Waiting for controller to apply MultiNetworkPolicy to restarted Pod (30 seconds)..."
sleep 30

log_info "🔎 === Checking Post-Restart Status (Pod Running, MultiNetworkPolicy Applied to New MAC) ==="
verify_ingress_rules_state "${RESTARTED_POD_MAC_GLOBAL}" "${EXPECTED_CHAIN_SUFFIX_GLOBAL}" "[Post-Restart]" "true" || exit 1

if [[ -n "$CONTROLLER_POD_NAME" ]]; then
    log_info "🔎 [Post-Restart] Checking NftPodChainMetadataCache for ${TARGET_POD_NAME} (MAC: ${RESTARTED_POD_MAC_GLOBAL})..."
    EXPECTED_CACHE_KEY_INGRESS_RESTART="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"
    
    RESTART_CACHE_LOGS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=2m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS_RESTART}" | tail -n 5 || echo "")

    INGRESS_COUNT_MATCH_RESTART=false
    EGRESS_COUNT_MATCH_FOR_INGRESS_KEY_RESTART=false
    ISOLATION_FLAG_MATCH_RESTART=false
    POLICY_RULE_COUNT_MATCH_RESTART=false

    if [[ -n "$RESTART_CACHE_LOGS" ]]
    then
        if echo "$RESTART_CACHE_LOGS" | grep -q "PolicyIngressRuleCount: 1"; then
            INGRESS_COUNT_MATCH_RESTART=true
        fi
        if echo "$RESTART_CACHE_LOGS" | grep -q "PolicyEgressRuleCount: 0"; then
            EGRESS_COUNT_MATCH_FOR_INGRESS_KEY_RESTART=true
        fi
        if echo "$RESTART_CACHE_LOGS" | grep -q "IsIsolationChain:false"; then
            ISOLATION_FLAG_MATCH_RESTART=true
        fi
         if echo "$RESTART_CACHE_LOGS" | grep -q "PolicyRuleCount:1"; then
            POLICY_RULE_COUNT_MATCH_RESTART=true
        fi
    fi

    if [[ "$INGRESS_COUNT_MATCH_RESTART" == true && \
          "$EGRESS_COUNT_MATCH_FOR_INGRESS_KEY_RESTART" == true && \
          "$ISOLATION_FLAG_MATCH_RESTART" == true && \
          "$POLICY_RULE_COUNT_MATCH_RESTART" == true ]]; then
        log_success "✔️ [Post-Restart] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS_RESTART} found and correct."
    else
        log_error "❌ [Post-Restart] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS_RESTART} missing or incorrect."
        log_info "   Logs found for key ${EXPECTED_CACHE_KEY_INGRESS_RESTART} (last recent lines):"
        echo "$RESTART_CACHE_LOGS"
        log_info "   Checked: PolicyIngressRuleCount:1 ($INGRESS_COUNT_MATCH_RESTART), PolicyEgressRuleCount:0 ($EGRESS_COUNT_MATCH_FOR_INGRESS_KEY_RESTART), IsIsolationChain:false ($ISOLATION_FLAG_MATCH_RESTART), PolicyRuleCount:1 ($POLICY_RULE_COUNT_MATCH_RESTART)"
        exit 1
    fi
else
    log_warn "⚠️ [Post-Restart] Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
