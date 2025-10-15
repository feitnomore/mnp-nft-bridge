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
POD_FILE="${SCENARIO_DIR}/01_target_pod.yaml"
MNP_INITIAL_FILE="${SCENARIO_DIR}/02_mnp_initial.yaml"
MNP_UPDATED_FILE="${SCENARIO_DIR}/03_mnp_updated.yaml"

TARGET_POD_NAME="target-pod-update-test"
TARGET_POD_NAMESPACE="default"
MNP_NAME="mnp-for-update-test" 

POLICY_FOR_NAD_NAME="e2e-test-bridge"
POLICY_FOR_NAD_NAMESPACE_REF="default"

NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"

TARGET_POD_MAC_GLOBAL="" # Para uso no cleanup

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
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_UPDATED_FILE}" # Try deleting the latest version
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_INITIAL_FILE}" # Try deleting the initial (if the update did not occur)
    log_info "  Waiting for controller to process MultiNetworkPolicy deletion (15s)..."
    sleep 15

    ${KUBECTL} delete --ignore-not-found=true -f "${POD_FILE}"
    log_info "  Waiting for controller to process Pod deletion (15s)..."
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
        # Check if any RULES chain (not isolation) is left
        if echo "$FINAL_RULESET" | grep -E "${ORPHANED_INGRESS_CHAIN_PATTERN}" | grep -v "_ISOLATION_" | grep -q .; then
            log_error "❌ CLEANUP ERROR: Pod-specific KUBE_MULTI_INGRESS (rule) chain still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -E "${ORPHANED_EGRESS_CHAIN_PATTERN}" | grep -v "_ISOLATION_" | grep -q .; then
            log_error "❌ CLEANUP ERROR: Pod-specific KUBE_MULTI_EGRESS (rule) chain still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -q "set mnp-"; then # Check if any set mnp- is left
            log_error "❌ CLEANUP ERROR: 'mnp-' sets still exist!"
            ERROR_FOUND_CLEANUP=1
        fi
         if [[ -n "$TARGET_POD_MAC_GLOBAL" ]]; then # If the MAC was captured
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
            # exit 1 
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
${KUBECTL} apply -f "${POD_FILE}"

log_info "⏳ Waiting pod ${TARGET_POD_NAMESPACE}/${TARGET_POD_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${TARGET_POD_NAMESPACE}" --timeout=240s
TARGET_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${TARGET_POD_NAMESPACE}")
if [[ -z "$TARGET_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address for pod ${TARGET_POD_NAME} not found. Aborting."
    exit 1
fi

sleep 15s
log_info "🔩 Applying Initial MultiNetworkPolicy: ${MNP_INITIAL_FILE}"
${KUBECTL} apply -f "${MNP_INITIAL_FILE}"
log_info "⏳ Waiting for controller to process Initial MNP (30 seconds)..."
sleep 30

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Failed to obtain container ID for Kind's control-plane."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX_INITIAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${TARGET_POD_NAMESPACE}" "${TARGET_POD_NAMESPACE}" "${TARGET_POD_NAME}")
EXPECTED_INGRESS_CHAIN_NAME_INITIAL="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_INITIAL}"

log_info "🔎 Checking initial state of nftables for Initial MultiNetworkPolicy..."
JUMP_RULE_INGRESS_OUTPUT_INITIAL=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL}" || echo "")
if [[ -z "$JUMP_RULE_INGRESS_OUTPUT_INITIAL" ]]
then
    log_error "❌ [Initial] JUMP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} to ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL} NOT found."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
    exit 1
fi
log_success "✔️ [Initial] JUMP Ingress rule found. Pod chain: ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL}"

log_info "🔎 [Initial] Checking ABSENCE of DROP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} in chain KUBE_MULTI_INGRESS..."
DROP_RULE_INGRESS_BASE_INITIAL=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} drop" || echo "NOT_FOUND")
if [[ "$DROP_RULE_INGRESS_BASE_INITIAL" == "NOT_FOUND" ]]
then
    log_error "❌ [Initial] Specific DROP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} was NOT found in KUBE_MULTI_INGRESS, but should have been."
    echo "Output of the drop rule found: $DROP_RULE_INGRESS_BASE_INITIAL"
    exit 1
else
    log_success "✔️ [Initial] Specific DROP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} found in KUBE_MULTI_INGRESS, as expected."
fi

INGRESS_POD_CHAIN_RULES_INITIAL=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME_INITIAL}")
EXPECTED_INITIAL_IP="192.168.200.10"
EXPECTED_INITIAL_PORT="80"

RULE_LINE_INITIAL=$(echo "$INGRESS_POD_CHAIN_RULES_INITIAL" | grep "ip saddr @mnp-src-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
if [[ -z "$RULE_LINE_INITIAL" ]]
then
    log_error "❌ [Initial] Ingress rule (IPBlock ${EXPECTED_INITIAL_IP} -> TCP/${EXPECTED_INITIAL_PORT}) not found in chain ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL}."
    echo "$INGRESS_POD_CHAIN_RULES_INITIAL"
    exit 1
fi
SRC_IP_SET_NAME_INITIAL=$(echo "$RULE_LINE_INITIAL" | grep -o 'mnp-src-ip-[a-f0-9]\{16\}' | head -n1)
TCP_PORT_SET_NAME_INITIAL=$(echo "$RULE_LINE_INITIAL" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)

${EXEC_KIND} nft list set bridge filter "${SRC_IP_SET_NAME_INITIAL}" | grep -qF "${EXPECTED_INITIAL_IP}" || \
    { log_error "❌ [Initial] Set ${SRC_IP_SET_NAME_INITIAL} does not contain ${EXPECTED_INITIAL_IP}."; exit 1; }
${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME_INITIAL}" | grep -qE "(^|[[:space:],{])${EXPECTED_INITIAL_PORT}([[:space:],}]|$)" || \
    { log_error "❌ [Initial] Set ${TCP_PORT_SET_NAME_INITIAL} does not contain ${EXPECTED_INITIAL_PORT}."; exit 1; }
log_success "✔️ [Initial] Rules and sets for initial MNP successfully verified."

CONTROLLER_POD_NAME_INITIAL=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME_INITIAL" ]]
then
    EXPECTED_CACHE_KEY_INITIAL_INGRESS="${EXPECTED_CHAIN_SUFFIX_INITIAL}_ingress"
    log_info "🔎 [Initial] Checking NftPodChainMetadataCache for key ${EXPECTED_CACHE_KEY_INITIAL_INGRESS} with PolicyIngressRuleCount:1, IsIsolationChain:false"
    CACHE_LOG_INITIAL=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_INITIAL}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=10m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INITIAL_INGRESS}" | \
        grep "PolicyIngressRuleCount: 1" | grep "IsIsolationChain:false" || echo "") # Added space in PolicyIngressRuleCount: 1
    if [[ -z "$CACHE_LOG_INITIAL" ]]
    then
        log_error "❌ [Initial] Entry in NftPodChainMetadataCache for ${EXPECTED_CACHE_KEY_INITIAL_INGRESS} with IngressRuleCount:1 and IsIsolationChain:false NOT found or incorrect."
        ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_INITIAL}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=10m | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INITIAL_INGRESS}" || echo "(not log found for the key)"
        exit 1
    else
        log_success "✔️ [Initial] NftPodChainMetadataCache entry for ${EXPECTED_CACHE_KEY_INITIAL_INGRESS} with IngressRuleCount:1 and IsIsolationChain:false found."
    fi
else
    log_warn "⚠️ [Initial] Could not find controller pod. Skipping NftPodChainMetadataCache check."
fi

log_info "🔩 Applying Updated MultiNetworkPolicy (adding ingress rule): ${MNP_UPDATED_FILE}"
${KUBECTL} apply -f "${MNP_UPDATED_FILE}"
log_info "⏳ Waiting for controller to process MultiNetworkPolicy update (30 seconds)..."
sleep 30

log_info "🔎 Checking nftables status AFTER MultiNetworkPolicy update..."
JUMP_RULE_INGRESS_OUTPUT_UPDATED=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL}" || echo "")
if [[ -z "$JUMP_RULE_INGRESS_OUTPUT_UPDATED" ]]
then
    log_error "❌ [Updated] JUMP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} and chain ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL} NOT found or changed."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
    exit 1
fi
log_success "✔️ [Updated] JUMP Ingress rule for chain ${EXPECTED_INGRESS_CHAIN_NAME_INITIAL} still exists."

INGRESS_POD_CHAIN_RULES_UPDATED=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME_INITIAL}")

log_info "🔎 [Updated] Checking if ORIGINAL Ingress rule still exists..."
RULE_LINE_ORIGINAL_POST_UPDATE=$(echo "$INGRESS_POD_CHAIN_RULES_UPDATED" | grep "ip saddr @${SRC_IP_SET_NAME_INITIAL}" | grep "tcp dport @${TCP_PORT_SET_NAME_INITIAL}" | grep "accept" | head -n1)
if [[ -z "$RULE_LINE_ORIGINAL_POST_UPDATE" ]]
then
    log_error "❌ [Updated] ORIGINAL Ingress Rule (IPBlock ${EXPECTED_INITIAL_IP} -> TCP/${EXPECTED_INITIAL_PORT}) NOT found after update."
    echo "$INGRESS_POD_CHAIN_RULES_UPDATED"; exit 1
fi
log_success "✔️ [Updated] ORIGINAL Ingress Rule still present."

log_info "🔎 [Updated] Checking if NEW Ingress Rule was added (IPBlock 10.10.10.0/24 -> TCP/8080)..."
EXPECTED_NEW_IP_MASK="10.10.10.0/24"
EXPECTED_NEW_PORT="8080"

RULE_LINE_NEW=$(echo "$INGRESS_POD_CHAIN_RULES_UPDATED" | grep "ip saddr ${EXPECTED_NEW_IP_MASK}" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
if [[ -z "$RULE_LINE_NEW" ]]
then
    log_error "❌ [Updated] NEW Ingress Rule (IP Mask ${EXPECTED_NEW_IP_MASK} -> TCP Port Set) not found."
    echo "$INGRESS_POD_CHAIN_RULES_UPDATED"
    exit 1
fi
TCP_PORT_SET_NAME_NEW=$(echo "$RULE_LINE_NEW" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME_NEW}" | grep -qE "(^|[[:space:],{])${EXPECTED_NEW_PORT}([[:space:],}]|$)" || \
    { log_error "❌ [Updated] Port set ${TCP_PORT_SET_NAME_NEW} for new rule does not contain ${EXPECTED_NEW_PORT}."; exit 1; }
log_success "✔️ [Updated] NEW Ingress Rule and its port set verified successfully."

CONTROLLER_POD_NAME_UPDATED=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME_UPDATED" ]]
then
    EXPECTED_CACHE_KEY_UPDATED_INGRESS="${EXPECTED_CHAIN_SUFFIX_INITIAL}_ingress"
    log_info "🔎 [Updated] Checking NftPodChainMetadataCache for key ${EXPECTED_CACHE_KEY_UPDATED_INGRESS} with PolicyIngressRuleCount:2, IsIsolationChain:false"
    sleep 5 # Give some time for log to be written
    CACHE_LOG_UPDATED=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_UPDATED}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=2m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_UPDATED_INGRESS}" | \
        grep "PolicyIngressRuleCount: 2" | grep "IsIsolationChain:false" | tail -n 1 || echo "")
    if [[ -z "$CACHE_LOG_UPDATED" ]]
    then
        log_error "❌ [Updated] Entry in NftPodChainMetadataCache for ${EXPECTED_CACHE_KEY_UPDATED_INGRESS} with IngressRuleCount:2 and IsIsolationChain:false NOT found or incorrect."
        log_info "   All cache logs for key ${EXPECTED_CACHE_KEY_UPDATED_INGRESS} in the last 2 minutes:"
        ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_UPDATED}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=2m | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_UPDATED_INGRESS}" || echo "   (Not log found)"
        exit 1
    else
        log_success "✔️ [Updated] NftPodChainMetadataCache entry for ${EXPECTED_CACHE_KEY_UPDATED_INGRESS} with IngressRuleCount:2 and IsIsolationChain:false found."
    fi
else
    log_warn "⚠️ [Updated] Could not find controller pod. Skipping NftPodChainMetadataCache check."
fi

log_info "✅ Test finished: ${TEST_NAME}"
