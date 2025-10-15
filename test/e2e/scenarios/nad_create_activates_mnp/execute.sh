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

# Scenario Variables
exit_code=0
trap 'exit_code=$?; cleanup; exit $exit_code' EXIT

export SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HACK_DIR="${SCENARIO_DIR}/../../../../hack"

POD_FILE="${SCENARIO_DIR}/00_target_pod_for_nad_test.yaml"
MNP_FILE="${SCENARIO_DIR}/01_mnp_waiting_for_nad.yaml"
NAD_FILE="${SCENARIO_DIR}/02_nad_for_policy_test_bridge.yaml"

TARGET_POD_NAME="target-pod-for-nad-test"
POD_NAMESPACE="default" 
MNP_NAME="policy-waiting-for-nad" 
MNP_NAMESPACE="default"

# The NAD and reference in the MNP/Pod use this name and namespace
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

    # Delete in reverse order of creation or securely
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
        # Usar NAD_NAMESPACE_IN_MANIFEST e NAD_NAME_IN_MANIFEST para a query jq
        mac_address=$(${KUBECTL} get pod "$pod_name" -n "$pod_ns" -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/network-status}' 2>/dev/null | \
                      jq -r --arg NAD_REF "${NAD_NAMESPACE_IN_MANIFEST}/${NAD_NAME_IN_MANIFEST}" '.[] | select(.name == $NAD_REF) | .mac' 2>/dev/null || echo "")
        if [[ -z "$mac_address" ]]; then # Fallback se o NAD for referenciado sem namespace (assumindo namespace do pod)
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

# 1. Initial Setup: Apply MultiNetworkPolicy and Pod. NetworkAttachmentDefinition will be applied LATER.
log_info "🔩 Applying MultiNetworkPolicy (referencing NetworkAttachmentDefinition that doesn't exist yet): ${MNP_FILE}"
${KUBECTL} apply -f "${MNP_FILE}"
log_info "🔩 Applying Pod (using NetworkAttachmentDefinition that doesn't exist yet): ${POD_FILE}"
${KUBECTL} apply -f "${POD_FILE}"

# The pod may not be Ready immediately if the NAD doesn't exist, or it may be Ready but without the secondary interface's IP/MAC.
# Let's give the pod some time to schedule itself and attempt to start.
log_info "⏳ Waiting for pod ${TARGET_POD_NAME} to be scheduled and attempt to start (30 seconds)..."
sleep 30 

# Check if the pod is at least created, even if not Ready
if ! ${KUBECTL} get pod "${TARGET_POD_NAME}" -n "${POD_NAMESPACE}" > /dev/null 2>&1; then
    log_error "❌ Pod ${TARGET_POD_NAME} was not created. Please check the configuration."
    exit 1
fi
log_info "✔️ Pod ${TARGET_POD_NAME} exists."

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Could not get Kind's control-plane ID."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${POD_NAMESPACE}" "${TARGET_POD_NAME}")
EXPECTED_INGRESS_CHAIN_NAME="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"

log_info "🔎 === Checking Initial State (MultiNetworkPolicy and Pod exist, NetworkAttachmentDefinition does NOT exist) ==="
log_info "🔎 [Initial] Checking for ABSENCE of JUMP Ingress for pod (MAC still unknown)..."
# Since the MAC may not be available yet, we check if *any* chain with the expected suffix has been created.
# Ideally, no nftables rules for this MNP/Pod should exist yet.
JUMP_RULE_INGRESS_INITIAL=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "jump ${EXPECTED_INGRESS_CHAIN_NAME}" || echo "NOT_FOUND")
if [[ "$JUMP_RULE_INGRESS_INITIAL" != "NOT_FOUND" ]]
then
    log_error "❌ [Initial] JUMP Ingress rule for ${EXPECTED_INGRESS_CHAIN_NAME} WAS found, but it shouldn't have been (NetworkAttachmentDefinition doesn't exist)."
    echo "Rule found: $JUMP_RULE_INGRESS_INITIAL"
    exit 1
fi
log_success "✔️ [Initial] No JUMP Ingress rule for ${EXPECTED_INGRESS_CHAIN_NAME} found, as expected."

# 2. Action: Create the referenced NetworkAttachmentDefinition
log_info "🔩 Creating NetworkAttachmentDefinition ${NAD_NAMESPACE_IN_MANIFEST}/${NAD_NAME_IN_MANIFEST}: ${NAD_FILE}"
${KUBECTL} apply -f "${NAD_FILE}"

log_info "⏳ Waiting for pod ${TARGET_POD_NAME} to be ready AFTER creating NetworkAttachmentDefinition..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${POD_NAMESPACE}" --timeout=240s
TARGET_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${POD_NAMESPACE}")
if [[ -z "$TARGET_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${TARGET_POD_NAME} not found after NetworkAttachmentDefinition creation."
    exit 1
fi

log_info "⏳ Waiting for controller to process NetworkAttachmentDefinition creation and apply MultiNetworkPolicy (30 seconds)..."
sleep 30

# 3. Post-Creation Checks of NetworkAttachmentDefinition
log_info "🔎 === Checking Status After NetworkAttachmentDefinition Creation (MultiNetworkPolicy must be applied) ==="
log_info "🔎 [Post-NAD Creation] Checking JUMP Ingress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME}..."
JUMP_RULE_INGRESS_POST_NAD=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME}" || echo "")
if [[ -z "$JUMP_RULE_INGRESS_POST_NAD" ]]
then
    log_error "❌ [Post-NAD Creation] JUMP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME} NOT found."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
    exit 1
fi
log_success "✔️ [Post-NAD Creation] JUMP Ingress rule found."

log_info "🔎 [Post-NAD Creation] Checking PRESENCE of DROP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} in KUBE_MULTI_INGRESS..."
DROP_RULE_INGRESS_BASE_POST_NAD=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} drop" || echo "NOT_FOUND")
if [[ "$DROP_RULE_INGRESS_BASE_POST_NAD" == "NOT_FOUND" ]]
then
    log_error "❌ [Post-NAD Creation] Specific DROP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} was NOT found in KUBE_MULTI_INGRESS, but it should have been."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
    exit 1
else
    log_success "✔️ [Post-NAD Creation] Specific DROP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} in KUBE_MULTI_INGRESS found, as expected."
fi

log_info "🔎 [Post-NAD Creation] Checking rules within chain ${EXPECTED_INGRESS_CHAIN_NAME}..."
INGRESS_POD_CHAIN_RULES_POST_NAD=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}")
EXPECTED_CIDR="192.168.100.70/32" # MultiNetworkPolicy CIDR
EXPECTED_PORT="80"                # MultiNetworkPolicy Port

RULE_LINE_POST_NAD=$(echo "$INGRESS_POD_CHAIN_RULES_POST_NAD" | grep "ip saddr @mnp-src-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
if [[ -z "$RULE_LINE_POST_NAD" ]]
then
    log_error "❌ [Post-NAD Creation] Ingress rule (IP Set to ${EXPECTED_CIDR%%/*} -> TCP Port Set to ${EXPECTED_PORT}) not found in chain ${EXPECTED_INGRESS_CHAIN_NAME}."
    echo "$INGRESS_POD_CHAIN_RULES_POST_NAD"
    exit 1
fi
SRC_IP_SET_NAME_POST_NAD=$(echo "$RULE_LINE_POST_NAD" | grep -o 'mnp-src-ip-[a-f0-9]\{16\}' | head -n1)
TCP_PORT_SET_NAME_POST_NAD=$(echo "$RULE_LINE_POST_NAD" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
if [[ -z "$SRC_IP_SET_NAME_POST_NAD" || -z "$TCP_PORT_SET_NAME_POST_NAD" ]]
then 
    log_error "❌ [Post-NAD Creation] Failed to extract set names from Ingress rule."
    exit 1; 
fi

${EXEC_KIND} nft list set bridge filter "${SRC_IP_SET_NAME_POST_NAD}" | grep -qF "${EXPECTED_CIDR%%/*}" || \
    { log_error "❌ [Post-NAD Creation] Set ${SRC_IP_SET_NAME_POST_NAD} does not contain ${EXPECTED_CIDR%%/*}."; exit 1; }
${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME_POST_NAD}" | grep -qE "(^|[[:space:],{])${EXPECTED_PORT}([[:space:],}]|$)" || \
    { log_error "❌ [Post-NAD Creation] Set ${TCP_PORT_SET_NAME_POST_NAD} does not contain port ${EXPECTED_PORT}."; exit 1; }
log_success "✔️ [Post-NAD Creation] Rules and sets for ${EXPECTED_INGRESS_CHAIN_NAME} checked."

# Check NftPodChainMetadataCache
CONTROLLER_POD_NAME=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME" ]]
then
    log_info "🔎 [Post-NAD Creation] Checking NftPodChainMetadataCache for ${TARGET_POD_NAME}..."
    EXPECTED_CACHE_KEY_INGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"
    
    CACHE_LOG_INGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" | \
        grep "PolicyIngressRuleCount: 1" | grep "PolicyEgressRuleCount: 0" | \
        grep "IsIsolationChain:false" | grep "PolicyRuleCount:1" | tail -n 1 || echo "")
        
    if [[ -z "$CACHE_LOG_INGRESS" ]]
    then
        log_error "❌ [Post-NAD Creation] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} missing or incorrect."
        ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" || echo "(no log for the key)"
        exit 1
    fi
    log_success "✔️ [Post-NAD Creation] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} found and correct."
else
    log_warn "⚠️ [Post-NAD Creation] Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
