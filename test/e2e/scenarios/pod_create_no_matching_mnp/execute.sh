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
IRRELEVANT_MNP_FILE="${SCENARIO_DIR}/01_mnp_irrelevant_policy.yaml" 
NEW_POD_FILE="${SCENARIO_DIR}/02_pod_other_app_bar.yaml"

NEW_POD_NAME="other-pod-app-bar"
POD_NAMESPACE="default" 

POLICY_FOR_NAD_NAME="e2e-test-bridge"
POLICY_FOR_NAD_NAMESPACE_REF="default"

NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"

NEW_POD_MAC_GLOBAL=""

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

    ${KUBECTL} delete --ignore-not-found=true -f "${NEW_POD_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${IRRELEVANT_MNP_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"
    
    log_info "  Checking if ruleset is clean after cleanup..."
    KIND_CONTROL_PLANE_ID_CLEANUP=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
    if [[ -n "$KIND_CONTROL_PLANE_ID_CLEANUP" ]]; then
        log_info "  Waiting a little longer for the reconciler (10s)..."
        sleep 10
        FINAL_RULESET=$(${EXEC_KIND} nft list ruleset bridge)
        
        ERROR_FOUND_CLEANUP=0
        # The irrelevant MultiNetworkPolicy (for app=foo) might have created chains/sets if an app=foo pod existed.
        # Since this test doesn't create an app=foo pod, we don't expect chains/sets from it.
        # The main check is that NOTHING related to NEW_POD_NAME (app=bar) was created or left behind.
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
        if [[ -n "$NEW_POD_MAC_GLOBAL" ]]; then 
            if echo "$FINAL_RULESET" | grep -q "ether daddr ${NEW_POD_MAC_GLOBAL}"; then
                 log_error "❌ CLEANUP ERROR: Ingress rule for MAC ${NEW_POD_MAC_GLOBAL} still exists!"
                 ERROR_FOUND_CLEANUP=1
            fi
             if echo "$FINAL_RULESET" | grep -q "ether saddr ${NEW_POD_MAC_GLOBAL}"; then
                 log_error "❌ CLEANUP ERROR: Egress rule for MAC ${NEW_POD_MAC_GLOBAL} still exists!"
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

${KUBECTL} apply -f "${NAD_FILE}"
log_info "🔩 Applying Irrelevant MultiNetworkPolicy (for app=foo): ${IRRELEVANT_MNP_FILE}"
${KUBECTL} apply -f "${IRRELEVANT_MNP_FILE}"
log_info "⏳ Waiting for irrelevant MultiNetworkPolicy to be assimilated (10 seconds)..."
sleep 10

log_info "🔩 Applying Pod (app=bar): ${NEW_POD_FILE}"
${KUBECTL} apply -f "${NEW_POD_FILE}"
log_info "⏳ Waiting for pod ${NEW_POD_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${NEW_POD_NAME}" -n "${POD_NAMESPACE}" --timeout=240s
NEW_POD_MAC_GLOBAL=$(get_pod_mac "${NEW_POD_NAME}" "${POD_NAMESPACE}")
if [[ -z "$NEW_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${NEW_POD_NAME} not found."
    exit 1
fi

log_info "⏳ Waiting for controller to process Pod creation (30 seconds)..."
sleep 30 

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Could not get container ID from Kind's control plane."
    exit 1
fi

log_info "🔎 === Checking State After Pod Creation (No MultiNetworkPolicy should apply) ==="

log_info "🔎 1. Checking for ABSENCE of JUMP Ingress for MAC ${NEW_POD_MAC_GLOBAL}..."
JUMP_RULE_INGRESS_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${NEW_POD_MAC_GLOBAL} jump KUBE_MULTI_INGRESS_" || echo "NOT_FOUND")
if [[ "$JUMP_RULE_INGRESS_OUTPUT" != "NOT_FOUND" ]]
then
    log_error "❌ JUMP Ingress rule for MAC ${NEW_POD_MAC_GLOBAL} WAS found, but it shouldn't have been."
    echo "Rule found: $JUMP_RULE_INGRESS_OUTPUT"
    exit 1
fi
log_success "✔️ No JUMP Ingress rule for MAC ${NEW_POD_MAC_GLOBAL} found, as expected."

log_info "🔎 2. Checking for ABSENCE of JUMP Egress for MAC ${NEW_POD_MAC_GLOBAL}..."
JUMP_RULE_EGRESS_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
    grep -F "ether saddr ${NEW_POD_MAC_GLOBAL} jump KUBE_MULTI_EGRESS_" || echo "NOT_FOUND")
if [[ "$JUMP_RULE_EGRESS_OUTPUT" != "NOT_FOUND" ]]
then
    log_error "❌ JUMP Egress rule for MAC ${NEW_POD_MAC_GLOBAL} WAS found, but it shouldn't have been."
    echo "Rule found: $JUMP_RULE_EGRESS_OUTPUT"
    exit 1
fi
log_success "✔️ No JUMP Egress rule for MAC ${NEW_POD_MAC_GLOBAL} found, as expected."

log_info "🔎 3. Checking for ABSENCE of specific DROP Ingress for MAC ${NEW_POD_MAC_GLOBAL} in KUBE_MULTI_INGRESS..."
DROP_RULE_INGRESS_BASE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${NEW_POD_MAC_GLOBAL} drop" || echo "NOT_FOUND")
if [[ "$DROP_RULE_INGRESS_BASE_OUTPUT" != "NOT_FOUND" ]]
then
    log_error "❌ Specific DROP Ingress rule for MAC ${NEW_POD_MAC_GLOBAL} WAS found, but it shouldn't have been."
    echo "Rule found: $DROP_RULE_INGRESS_BASE_OUTPUT"
    exit 1
fi
log_success "✔️ No specific DROP Ingress rule for MAC ${NEW_POD_MAC_GLOBAL} found, as expected."

log_info "🔎 4. Checking ABSENCE of specific DROP Egress for MAC ${NEW_POD_MAC_GLOBAL} in KUBE_MULTI_EGRESS..."
DROP_RULE_EGRESS_BASE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
    grep -F "ether saddr ${NEW_POD_MAC_GLOBAL} drop" || echo "NOT_FOUND")
if [[ "$DROP_RULE_EGRESS_BASE_OUTPUT" != "NOT_FOUND" ]]
then
    log_error "❌ Specific DROP Egress rule for MAC ${NEW_POD_MAC_GLOBAL} WAS found, but it shouldn't have been."
    echo "Rule found: $DROP_RULE_EGRESS_BASE_OUTPUT"
    exit 1
fi
log_success "✔️ No specific DROP Egress rule for MAC ${NEW_POD_MAC_GLOBAL} found, as expected."

log_info "🔎 5. Checking for ABSENCE of pod-specific chains (KUBE_MULTI_INGRESS/EGRESS with any hash) for this pod..."
CONTROLLER_POD_NAME=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME" ]]
then
    log_info "🔎 Checking NftPodChainMetadataCache for missing entries for ${NEW_POD_NAME}..."
    # Use a placeholder MultiNetworkPolicy name to generate a potential suffix, since no actual MultiNetworkPolicy applies.
    # The irrelevant MultiNetworkPolicy name is "irrelevant-policy-for-app-foo"
    POTENTIAL_SUFFIX=$(generate_pod_chain_suffix "irrelevant-policy-for-app-foo" "${POD_NAMESPACE}" "${POD_NAMESPACE}" "${NEW_POD_NAME}")
    EXPECTED_CACHE_KEY_INGRESS_ABSENT="${POTENTIAL_SUFFIX}_ingress"
    EXPECTED_CACHE_KEY_EGRESS_ABSENT="${POTENTIAL_SUFFIX}_egress"

    RECENT_LOG_INGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=2m | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS_ABSENT}" || echo "KEY_NOT_ADDED_RECENTLY")
    RECENT_LOG_EGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=2m | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_EGRESS_ABSENT}" || echo "KEY_NOT_ADDED_RECENTLY")

    if [[ "$RECENT_LOG_INGRESS" != "KEY_NOT_ADDED_RECENTLY" ]]
    then
        log_error "❌ [Cache] Ingress entry for a potential key for ${NEW_POD_NAME} was recently added/updated, but it shouldn't have been."
        echo "Log found: $RECENT_LOG_INGRESS"
        exit 1
    fi
    log_success "✔️ [Cache] No recent Ingress entries in cache for ${NEW_POD_NAME}, as expected."

    if [[ "$RECENT_LOG_EGRESS" != "KEY_NOT_ADDED_RECENTLY" ]]
    then
        log_error "❌ [Cache] Egress entry for a potential key for ${NEW_POD_NAME} was recently added/updated, but should not have been."
        echo "Log found: $RECENT_LOG_EGRESS"
        exit 1
    fi
    log_success "✔️ [Cache] No recent Egress entries in cache for ${NEW_POD_NAME}, as expected."
else
    log_warn "⚠️ Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
