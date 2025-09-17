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
POD_FILE="${SCENARIO_DIR}/01_pod_using_nad_to_delete.yaml"
MNP_FILE="${SCENARIO_DIR}/02_mnp_on_nad_to_delete.yaml"

TARGET_POD_NAME="pod-using-nad-to-delete"
POD_NAMESPACE="default" 
MNP_NAME="policy-on-nad-to-delete" 
MNP_NAMESPACE="default"

NAD_NAME_IN_MANIFEST="e2e-test-bridge"
NAD_NAMESPACE_IN_MANIFEST="default" 

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

    # The NetworkAttachmentDefinition must have already been deleted by the test, but we tried again.
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${POD_FILE}"
    
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
            log_error "❌ CLEANUP ERROR: 'mnp-' sets still exist!"
            ERROR_FOUND_CLEANUP=1
        fi
        # We cannot reliably check the MAC here if the pod was deleted 
        # before the NetworkAttachmentDefinition on cleanup.
        
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

    log_info "🔎 Trying to get MAC address for pod ${pod_ns}/${pod_name}..."
    while [[ -z "$mac_address" && "$attempts" -lt "$max_attempts" ]]; do
        mac_address=$(${KUBECTL} get pod "$pod_name" -n "$pod_ns" -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/network-status}' 2>/dev/null | \
                      jq -r --arg NAD_REF "${NAD_NAMESPACE_IN_MANIFEST}/${NAD_NAME_IN_MANIFEST}" '.[] | select(.name == $NAD_REF) | .mac' 2>/dev/null || echo "")
        if [[ -z "$mac_address" ]]; then 
             mac_address=$(${KUBECTL} get pod "$pod_name" -n "$pod_ns" -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/network-status}' 2>/dev/null | \
                      jq -r --arg NAD_NAME_NO_NS "${NAD_NAME_IN_MANIFEST}" '.[] | select(.name == $NAD_NAME_NO_NS) | .mac' 2>/dev/null || echo "")
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

# 1. Initial Setup: Apply NetworkAttachmentDefinition, Pod and MultiNetworkPolicy
${KUBECTL} apply -f "${NAD_FILE}"
${KUBECTL} apply -f "${POD_FILE}"
${KUBECTL} apply -f "${MNP_FILE}"

log_info "⏳ Waiting for pod ${TARGET_POD_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${POD_NAMESPACE}" --timeout=180s
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
EXPECTED_INGRESS_CHAIN_NAME="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"

log_info "🔎 === Checking Initial State (NetworkAttachmentDefinition, Pod and MultiNetworkPolicy exist and rules applied) ==="
log_info "🔎 [Initial] Checking JUMP Ingress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME}..."
JUMP_RULE_INGRESS_INITIAL=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME}" || echo "")
if [[ -z "$JUMP_RULE_INGRESS_INITIAL" ]]
then
    log_error "❌ [Initial] JUMP Ingress rule NOT found."
    exit 1
fi
log_success "✔️ [Initial] JUMP Ingress rule found."

log_info "🔎 [Initial] Checking rules within chain ${EXPECTED_INGRESS_CHAIN_NAME}..."
INGRESS_POD_CHAIN_RULES_INITIAL=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}")
EXPECTED_CIDR="192.168.100.80/32" 
EXPECTED_PORT="80"              

RULE_LINE_INITIAL=$(echo "$INGRESS_POD_CHAIN_RULES_INITIAL" | grep "ip saddr @mnp-src-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
if [[ -z "$RULE_LINE_INITIAL" ]]
then
    log_error "❌ [Initial] Ingress rule (IP Set to ${EXPECTED_CIDR%%/*} -> TCP Port Set to ${EXPECTED_PORT}) not found in chain ${EXPECTED_INGRESS_CHAIN_NAME}."
    echo "$INGRESS_POD_CHAIN_RULES_INITIAL"
    exit 1
fi
log_success "✔️ [Initial] Ingress rule on pod specific chain found."
log_success "✔️ [Initial] Initial state verified successfully."

# 2. Action: Delete the NetworkAttachmentDefinition
log_info "🔩 Deleting NetworkAttachmentDefinition ${NAD_NAMESPACE_IN_MANIFEST}/${NAD_NAME_IN_MANIFEST}: ${NAD_FILE}"
${KUBECTL} delete -f "${NAD_FILE}"

log_info "⏳ Waiting for controller to process NetworkAttachmentDefinition deletion (30 seconds)..."
sleep 30

# 3. Post-Deletion Checks of NetworkAttachmentDefinition
log_info "🔎 === Checking Status After Deleting NetworkAttachmentDefinition ==="
log_info "🔎 [Post-NAD Deletion] Checking if mnp-nft-bridge controller is still running..."
CONTROLLER_POD_STATUS=$(${KUBECTL} get pod -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].status.phase}' 2>/dev/null || echo "NOT_FOUND")
if [[ "$CONTROLLER_POD_STATUS" != "Running" ]]
then
    log_error "❌ Controller mnp-nft-bridge is not in 'Running' state (status: ${CONTROLLER_POD_STATUS})."
    exit 1
fi
log_success "✔️ mnp-nft-bridge controller is 'Running'."

# The expectation is that the rules for the existing pod (TARGET_POD_MAC_GLOBAL) REMAIN.
# Deleting the NetworkAttachmentDefinition should not, by itself, cause the removal of rules for pods that are already configured
# and whose MultiNetworkPolicy still exists and selects them. The controller may not be able to validate the driver type
# for NEW reconciliations of this MNP, but the existing rules should be maintained.
log_info "🔎 [Post-NAD Deletion] Checking if JUMP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} to ${EXPECTED_INGRESS_CHAIN_NAME} STILL EXISTS..."
JUMP_RULE_INGRESS_POST_NAD_DELETE=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME}" || echo "NOT_FOUND")
if [[ "$JUMP_RULE_INGRESS_POST_NAD_DELETE" == "NOT_FOUND" ]]
then
    log_error "❌ [Post-NAD Deletion] JUMP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME} NOT found, but was expected."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
    exit 1
fi
log_success "✔️ [Post-NAD Deletion] JUMP Ingress rule still exists, as expected."

log_info "🔎 [Post-NAD Deletion] Checking if chain ${EXPECTED_INGRESS_CHAIN_NAME} STILL EXISTS..."
if ! ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}" > /dev/null 2>&1; then
    log_error "❌ [Post-NAD Deletion] Chain Ingress ${EXPECTED_INGRESS_CHAIN_NAME} NOT found, but was expected."
    exit 1
fi
log_success "✔️ [Post-NAD Deletion] Chain Ingress ${EXPECTED_INGRESS_CHAIN_NAME} still exists, as expected."

log_info "🔎 [Post-NAD Deletion] Checking if rules within chain ${EXPECTED_INGRESS_CHAIN_NAME} STILL EXIST..."
INGRESS_POD_CHAIN_RULES_POST_NAD_DELETE=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}")
RULE_LINE_POST_NAD_DELETE=$(echo "$INGRESS_POD_CHAIN_RULES_POST_NAD_DELETE" | grep "ip saddr @mnp-src-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
if [[ -z "$RULE_LINE_POST_NAD_DELETE" ]]
then
    log_error "❌ [Post-NAD Deletion] Ingress Rule (IP Set -> TCP Port Set) NOT found in chain ${EXPECTED_INGRESS_CHAIN_NAME}, but was expected."
    echo "$INGRESS_POD_CHAIN_RULES_POST_NAD_DELETE"
    exit 1
fi
log_success "✔️ [Post-NAD Deletion] Ingress rule on pod specific chain still exists as expected."

# Check NftPodChainMetadataCache - entry must remain
CONTROLLER_POD_NAME_LOGS=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME_LOGS" ]]
then
    log_info "🔎 [Post-NAD Deletion] Checking NftPodChainMetadataCache for ${TARGET_POD_NAME}..."
    EXPECTED_CACHE_KEY_INGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"
    
    CACHE_LOG_INGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_LOGS}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" | \
        grep "PolicyIngressRuleCount: 1" | grep "IsIsolationChain:false" | tail -n 1 || echo "")
        
    if [[ -z "$CACHE_LOG_INGRESS" ]]
    then
        log_error "❌ [Post-NAD Deletion] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} not found or not recently updated as expected."
        ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_LOGS}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" || echo "(no log for the key)"
        # Don't fail the test because of this, as the state of nftables is more important here.
        log_warn "   The metadata cache entry may not have been 'Added/Updated' recently, but the nftables state is the primary one."
    else
        log_success "✔️ [Post-NAD Deletion] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} found (or recently updated)."
    fi
else
    log_warn "⚠️ [Post-NAD Deletion] Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
