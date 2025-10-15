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
NS_TARGET_FILE="${SCENARIO_DIR}/01_ns_target_for_ns_delete_test.yaml"
TARGET_POD_FILE="${SCENARIO_DIR}/02_target_pod_in_ns_target_delete.yaml"
NS_CLIENT_FILE="${SCENARIO_DIR}/03_ns_client_to_delete.yaml" 
CLIENT_POD_FILE="${SCENARIO_DIR}/04_client_pod_in_ns_to_delete.yaml"
MNP_FILE="${SCENARIO_DIR}/05_mnp_affected_by_ns_delete.yaml"

TARGET_POD_NAME="target-pod-in-ns-target-delete"
TARGET_POD_NAMESPACE="ns-target-for-ns-delete-test" 

CLIENT_POD_NAME="client-pod-in-ns-to-delete"
CLIENT_POD_NAMESPACE_TO_DELETE="ns-client-to-delete"

MNP_NAME="policy-affected-by-ns-delete" 
MNP_NAMESPACE="ns-target-for-ns-delete-test"

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

    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_FILE}"
    ${KUBECTL} delete pod "${CLIENT_POD_NAME}" -n "${CLIENT_POD_NAMESPACE_TO_DELETE}" --ignore-not-found=true
    ${KUBECTL} delete ns "${CLIENT_POD_NAMESPACE_TO_DELETE}" --ignore-not-found=true
    ${KUBECTL} delete --ignore-not-found=true -f "${TARGET_POD_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NS_TARGET_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"
    
    log_info "  Checking if ruleset is clean after cleanup..."
    KIND_CONTROL_PLANE_ID_CLEANUP=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
    if [[ -n "$KIND_CONTROL_PLANE_ID_CLEANUP" ]]
    then
        log_info "  Waiting a little longer for the reconciler (10s)..."
        sleep 10
        FINAL_RULESET=$( ${EXEC_KIND} nft list ruleset bridge)
        
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

${KUBECTL} apply -f "${NAD_FILE}"
${KUBECTL} apply -f "${NS_TARGET_FILE}"
${KUBECTL} apply -f "${NS_CLIENT_FILE}" 
${KUBECTL} apply -f "${TARGET_POD_FILE}"
${KUBECTL} apply -f "${CLIENT_POD_FILE}" 

log_info "⏳ Waiting for pod ${TARGET_POD_NAME} in ${TARGET_POD_NAMESPACE} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${TARGET_POD_NAMESPACE}" --timeout=240s
TARGET_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${TARGET_POD_NAMESPACE}")
if [[ -z "$TARGET_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${TARGET_POD_NAME} not found."
    exit 1
fi

log_info "⏳ Waiting for pod ${CLIENT_POD_NAME} in ${CLIENT_POD_NAMESPACE_TO_DELETE} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${CLIENT_POD_NAME}" -n "${CLIENT_POD_NAMESPACE_TO_DELETE}" --timeout=240s
CLIENT_POD_MAC_GLOBAL=$(get_pod_mac "${CLIENT_POD_NAME}" "${CLIENT_POD_NAMESPACE_TO_DELETE}")
if [[ -z "$CLIENT_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${CLIENT_POD_NAME} not found."
    exit 1
fi

log_info "🔩 Applying MultiNetworkPolicy (with namespaceSelector env=client-delete): ${MNP_FILE}"
${KUBECTL} apply -f "${MNP_FILE}"

log_info "⏳ Waiting for controller to process MultiNetworkPolicy and Pods (30 seconds)..."
sleep 30

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Unable to get Kind's control-plane ID."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${TARGET_POD_NAMESPACE}" "${TARGET_POD_NAME}")
EXPECTED_INGRESS_CHAIN_NAME="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"

log_info "🔎 === Checking Initial State (MultiNetworkPolicy applied, Client Namespace and Client Pod exist) ==="
log_info "🔎 [Initial] Checking JUMP Ingress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME}..."
JUMP_RULE_INGRESS_INITIAL=$( ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME}" || echo "")
if [[ -z "$JUMP_RULE_INGRESS_INITIAL" ]]
then
    log_error "❌ [Initial] JUMP Ingress rule NOT found."
    exit 1
fi
log_success "✔️ [Initial] JUMP Ingress rule found."

log_info "🔎 [Initial] Checking rules within chain ${EXPECTED_INGRESS_CHAIN_NAME}..."
INGRESS_POD_CHAIN_RULES_INITIAL=$( ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}")
EXPECTED_PORT_MNP="80"

RULE_LINE_INITIAL=$(echo "$INGRESS_POD_CHAIN_RULES_INITIAL" | grep "ether saddr @mnp-src-mac-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
if [[ -z "$RULE_LINE_INITIAL" ]]
then
    log_error "❌ [Initial] Ingress rule (MAC Set -> TCP Port Set) not found in chain ${EXPECTED_INGRESS_CHAIN_NAME}."
    echo "$INGRESS_POD_CHAIN_RULES_INITIAL"
    exit 1
fi
SRC_MAC_SET_NAME_GLOBAL=$(echo "$RULE_LINE_INITIAL" | grep -o 'mnp-src-mac-[a-f0-9]\{16\}' | head -n1) 
TCP_PORT_SET_NAME_INITIAL=$(echo "$RULE_LINE_INITIAL" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
if [[ -z "$SRC_MAC_SET_NAME_GLOBAL" || -z "$TCP_PORT_SET_NAME_INITIAL" ]]
then 
    log_error "❌ [Initial] Failed to extract set names from Ingress rule."
    exit 1
fi

log_info "🔎 [Initial] Checking contents of Source MAC Set ${SRC_MAC_SET_NAME_GLOBAL}..."
SET_CONTENT_INITIAL=$( ${EXEC_KIND} nft list set bridge filter "${SRC_MAC_SET_NAME_GLOBAL}" 2>/dev/null || echo "SET_ERROR_INITIAL")
if [[ "$SET_CONTENT_INITIAL" == "SET_ERROR_INITIAL" ]]
then
    log_error "❌ [Initial] Failed to list source MAC set ${SRC_MAC_SET_NAME_GLOBAL}."
    exit 1
fi
if ! echo "$SET_CONTENT_INITIAL" | grep -qF "${CLIENT_POD_MAC_GLOBAL}"
then
    log_error "❌ [Initial] Set ${SRC_MAC_SET_NAME_GLOBAL} does not contain the Client Pod MAC (${CLIENT_POD_MAC_GLOBAL})."; 
    echo "Set content:"
    echo "$SET_CONTENT_INITIAL"
    exit 1
fi
log_success "✔️ [Initial] Set ${SRC_MAC_SET_NAME_GLOBAL} contains the MAC of the Client Pod."
log_success "✔️ [Initial] Initial state verified successfully."


log_info "🔩 Deleting Client Namespace: ${CLIENT_POD_NAMESPACE_TO_DELETE}"
${KUBECTL} delete namespace "${CLIENT_POD_NAMESPACE_TO_DELETE}"
log_info "⏳ Waiting for controller to process Namespace and Client Pod deletion (30 seconds)..."
sleep 30

log_info "🔎 === Checking Status After Deleting the Client Namespace ==="
log_info "🔎 [Post-Delete Namespace] Checking JUMP Ingress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME} (must still exist)..."
JUMP_RULE_INGRESS_POST_NS_DELETE=$( ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME}" || echo "")
if [[ -z "$JUMP_RULE_INGRESS_POST_NS_DELETE" ]]
then 
    log_error "❌ [Post-Delete Namespace] JUMP Ingress rule for ${EXPECTED_INGRESS_CHAIN_NAME} NOT found, but was expected."
    exit 1 
fi
log_success "✔️ [Post-Delete Namespace] JUMP Ingress rule for ${EXPECTED_INGRESS_CHAIN_NAME} still exists."

log_info "🔎 [Post-Delete Namespace] Checking contents of chain ${EXPECTED_INGRESS_CHAIN_NAME}..."
INGRESS_POD_CHAIN_RULES_POST_NS_DELETE=$( ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}")

log_info "🔎 [Post-Delete Namespace] Checking if Source MAC Set ${SRC_MAC_SET_NAME_GLOBAL} is EMPTY..."
# An empty set will not have the line "elements = { ... }" or will have "elements = { }"
SET_CONTENT_POST_NS_DELETE=$( ${EXEC_KIND} nft list set bridge filter "${SRC_MAC_SET_NAME_GLOBAL}" 2>/dev/null || echo "SET_DOES_NOT_EXIST")

SET_IS_CONFIRMED_EMPTY=false
if [[ "$SET_CONTENT_POST_NS_DELETE" == "SET_DOES_NOT_EXIST" ]]
then
    # If the controller deletes empty sets, that's OK.
    log_warn "⚠️ [Post-Delete Namespace] Source MAC Set ${SRC_MAC_SET_NAME_GLOBAL} no longer exists. Assuming it was deleted because it was empty."
    SET_IS_CONFIRMED_EMPTY=true # We consider this as "empty" for the purpose of testing
elif ! echo "$SET_CONTENT_POST_NS_DELETE" | grep -q "elements = {"; then
    # If the line "elements = {" is NOT present, the set is empty.
    log_success "✔️ [Post-Delete Namespace] Source MAC Set ${SRC_MAC_SET_NAME_GLOBAL} is empty (does not contain 'elements = {')."
    SET_IS_CONFIRMED_EMPTY=true
elif echo "$SET_CONTENT_POST_NS_DELETE" | grep -q "elements = { }"; then
    # If the line "elements = { }" IS present, the set is explicitly empty.
    log_success "✔️ [Post-Delete Namespace] Source MAC Set ${SRC_MAC_SET_NAME_GLOBAL} is explicitly empty (contains 'elements = { }')."
    SET_IS_CONFIRMED_EMPTY=true
fi

if [[ "$SET_IS_CONFIRMED_EMPTY" != true ]]
then
    log_error "❌ [Post-Delete Namespace] Source MAC Set ${SRC_MAC_SET_NAME_GLOBAL} is not empty and has not been deleted as expected."
    echo "Set content:"
    echo "$SET_CONTENT_POST_NS_DELETE"
    exit 1
fi

log_info "🔎 [Post-Delete Namespace] Checking if chain ${EXPECTED_INGRESS_CHAIN_NAME} is EMPTY (no accept rules)..."
# Extract only the lines BETWEEN the keys of the specific chain definition, remove spaces and empty lines
INNER_CHAIN_CONTENT=$(echo "$INGRESS_POD_CHAIN_RULES_POST_NS_DELETE" | \
    sed -n "/chain ${EXPECTED_INGRESS_CHAIN_NAME} {/,/}/p" | \
    sed "1d;\$d" | tr -d '[:space:]')

if [[ -z "$INNER_CHAIN_CONTENT" ]]
then
    log_success "✔️ [Post-Delete Namespace] Chain ${EXPECTED_INGRESS_CHAIN_NAME} is empty, as expected."
else
    log_error "❌ [Post-Delete Namespace] Chain ${EXPECTED_INGRESS_CHAIN_NAME} is NOT empty, but it should be."
    echo "Chain content:"
    echo "$INNER_CHAIN_CONTENT"
    exit 1
fi


CONTROLLER_POD_NAME=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME" ]]
then
    log_info "🔎 [Post-Delete Namespace] Checking NftPodChainMetadataCache for ${TARGET_POD_NAME}..."
    EXPECTED_CACHE_KEY_INGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"
    
    CACHE_LOG_INGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" | \
        grep "PolicyIngressRuleCount: 1" | grep "IsIsolationChain:false" | tail -n 1 || echo "")
        
    if [[ -z "$CACHE_LOG_INGRESS" ]]
    then
        log_error "❌ [Post-Delete Namespace] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} missing or incorrect."
        exit 1
    fi
    log_success "✔️ [Post-Delete Namespace] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} still exists and appears correct."
else
    log_warn "⚠️ [Post-Delete Namespace] Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
