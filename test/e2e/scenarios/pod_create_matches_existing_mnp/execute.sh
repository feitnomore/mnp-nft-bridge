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
MNP_FILE="${SCENARIO_DIR}/01_mnp_allow_app_foo.yaml"
POD_FILE="${SCENARIO_DIR}/02_pod_new_app_foo.yaml"

NEW_POD_NAME="new-pod-app-foo"
POD_NAMESPACE="default" 
MNP_NAME="allow-app-foo" 
MNP_NAMESPACE="default"

POLICY_FOR_NAD_NAME="e2e-test-bridge" # Name of the NetworkAttachmentDefinition referenced in the MultiNetworkPolicy and Pod
POLICY_FOR_NAD_NAMESPACE_REF="default"

NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"

NEW_POD_MAC_GLOBAL=""
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
        
        ORPHANED_INGRESS_CHAIN_PATTERN="KUBE_MULTI_INGRESS_[0-9a-fA-F]{12}"
        ERROR_FOUND_CLEANUP=0
        if echo "$FINAL_RULESET" | grep -E "${ORPHANED_INGRESS_CHAIN_PATTERN}" | grep -v "_ISOLATION_" | grep -q .; then
            log_error "❌ CLEANUP ERROR: Pod-specific KUBE_MULTI_INGRESS (rule) chain still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -q "set mnp-"; then
            log_error "❌ CLEANUP ERROR: 'mnp-' sets still exist!"
            ERROR_FOUND_CLEANUP=1
        fi
        if [[ -n "$NEW_POD_MAC_GLOBAL" ]]; then 
            if echo "$FINAL_RULESET" | grep -q "ether daddr ${NEW_POD_MAC_GLOBAL} jump"; then
                 log_error "❌ CLEANUP ERROR: JUMP Ingress rule for MAC ${NEW_POD_MAC_GLOBAL} still exists!"
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

# 1. Initial Setup: Apply NetworkAttachmentDefinitionOne MultiNetworkPolicy first
${KUBECTL} apply -f "${NAD_FILE}"
log_info "🔩 Applying Multi Network Policy (allow-app-foto): ${MNP_FILE}"
${KUBECTL} apply -f "${MNP_FILE}"
log_info "⏳ Waiting for MultiNetworkPolicy to be ingested/cached by the controller (10 seconds)..."
sleep 10

# 2. Action: Create the Pod that matches the MultiNetworkPolicy
log_info "🔩 Applying Pod (new-pod-app-foo): ${POD_FILE}"
${KUBECTL} apply -f "${POD_FILE}"
log_info "⏳ Waiting for pod ${NEW_POD_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${NEW_POD_NAME}" -n "${POD_NAMESPACE}" --timeout=240s
NEW_POD_MAC_GLOBAL=$(get_pod_mac "${NEW_POD_NAME}" "${POD_NAMESPACE}")
if [[ -z "$NEW_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${NEW_POD_NAME} not found."
    exit 1
fi

log_info "⏳ Waiting for controller to process Pod creation and apply MultiNetworkPolicy (30 seconds)..."
sleep 30

# 3. Checks
KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Could not get container ID from Kind's control plane."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${POD_NAMESPACE}" "${NEW_POD_NAME}")
EXPECTED_INGRESS_CHAIN_NAME="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"
# This MultiNetworkPolicy only has Ingress
# EXPECTED_EGRESS_CHAIN_NAME="KUBE_MULTI_EGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}" 

log_info "🔎 === Checking Status After Pod Creation ==="
log_info "🔎 Checking INGRESS rules for pod ${POD_NAMESPACE}/${NEW_POD_NAME} (MAC: ${NEW_POD_MAC_GLOBAL})"

JUMP_RULE_INGRESS_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${NEW_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME}" || echo "")
if [[ -z "$JUMP_RULE_INGRESS_OUTPUT" ]]
then
    log_error "❌ JUMP Ingress rule for MAC ${NEW_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME} NOT found."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
    exit 1
fi
log_success "✔️ Ingress JUMP rule found. Ingress pod chain: ${EXPECTED_INGRESS_CHAIN_NAME}"

log_info "🔎 Checking PRESENCE of DROP Ingress rule for MAC ${NEW_POD_MAC_GLOBAL} in KUBE_MULTI_INGRESS chain..."
DROP_RULE_INGRESS_BASE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${NEW_POD_MAC_GLOBAL} drop" || echo "NOT_FOUND")
if [[ "$DROP_RULE_INGRESS_BASE_OUTPUT" == "NOT_FOUND" ]]
then
    log_error "❌ Specific DROP Ingress rule for MAC ${NEW_POD_MAC_GLOBAL} was NOT found in KUBE_MULTI_INGRESS, but should have been."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
    exit 1
else
    log_success "✔️ Specific DROP Ingress rule for MAC ${NEW_POD_MAC_GLOBAL} found in KUBE_MULTI_INGRESS, as expected."
fi

log_info "🔎 Checking rules within chain ${EXPECTED_INGRESS_CHAIN_NAME}..."
INGRESS_POD_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}")
EXPECTED_CIDR="192.168.100.10/32" # This is /32, it will go to a set
EXPECTED_PORT="80"

RULE_LINE=$(echo "$INGRESS_POD_CHAIN_RULES" | grep "ip saddr @mnp-src-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
if [[ -z "$RULE_LINE" ]]
then
    log_error "❌ Ingress rule (IP Set to ${EXPECTED_CIDR%%/*} -> TCP Port Set to ${EXPECTED_PORT}) not found in chain ${EXPECTED_INGRESS_CHAIN_NAME}."
    echo "$INGRESS_POD_CHAIN_RULES"
    exit 1
fi
SRC_IP_SET_NAME=$(echo "$RULE_LINE" | grep -o 'mnp-src-ip-[a-f0-9]\{16\}' | head -n1)
TCP_PORT_SET_NAME=$(echo "$RULE_LINE" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
if [[ -z "$SRC_IP_SET_NAME" || -z "$TCP_PORT_SET_NAME" ]]
then
    log_error "❌ Failed to extract set names from Ingress rule."
    exit 1
fi

${EXEC_KIND} nft list set bridge filter "${SRC_IP_SET_NAME}" | grep -qF "${EXPECTED_CIDR%%/*}" || \
    { log_error "❌ Set ${SRC_IP_SET_NAME} does not contain ${EXPECTED_CIDR%%/*}."; exit 1; }
${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME}" | grep -qE "(^|[[:space:],{])${EXPECTED_PORT}([[:space:],}]|$)" || \
    { log_error "❌ Set ${TCP_PORT_SET_NAME} does not contain port ${EXPECTED_PORT}."; exit 1; }
log_success "✔️ Rules and sets for ${EXPECTED_INGRESS_CHAIN_NAME} checked."

# Since MultiNetworkPolicy only has Ingress, there should be no specific Egress chain for this pod/MultiNetworkPolicy
log_info "🔎 Checking for ABSENCE of specific Egress chain (KUBE_MULTI_EGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL})..."
if ${EXEC_KIND} nft list chain bridge filter "KUBE_MULTI_EGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}" > /dev/null 2>&1; then
    log_error "❌ Egress chain KUBE_MULTI_EGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL} WAS found, but it shouldn't have been (MultiNetworkPolicy is Ingress only)."
    exit 1
fi
log_success "✔️ No specific Egress chain KUBE_MULTI_EGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL} found, as expected."

# Checking NftPodChainMetadataCache
CONTROLLER_POD_NAME=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME" ]]; then
    log_info "🔎 Checking NftPodChainMetadataCache for ${NEW_POD_NAME}..."
    EXPECTED_CACHE_KEY_INGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"
    
    # MultiNetworkPolicy has 1 ingress rule, 0 egress rule
    CACHE_LOG_INGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" | \
        grep "PolicyIngressRuleCount: 1" | grep "PolicyEgressRuleCount: 0" | grep "IsIsolationChain:false" | tail -n 1 || echo "")
        
    if [[ -z "$CACHE_LOG_INGRESS" ]]
    then
        log_error "❌ Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} missing or incorrect (expected Ingress:1, Egress:0, IsIsolation:false)."
        ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" || echo "(no log for the key)"
        exit 1
    fi
    log_success "✔️ Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} found and correct."

    # There should be no Egress entry in the cache for this suffix
    EXPECTED_CACHE_KEY_EGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_egress"
    CACHE_LOG_EGRESS_ABSENT=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=1m | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_EGRESS}" || echo "EGRESS_KEY_NOT_ADDED_RECENTLY")
    if [[ "$CACHE_LOG_EGRESS_ABSENT" != "EGRESS_KEY_NOT_ADDED_RECENTLY" ]]
    then
        log_warn "⚠️ [Cache] Egress key ${EXPECTED_CACHE_KEY_EGRESS} was recently added/updated, but should not exist for this MultiNetworkPolicy."
        # Don't fail the test because of this, but it is a point of attention.
    else
        log_success "✔️ [Cache] No recent Add/Update entry for Egress key ${EXPECTED_CACHE_KEY_EGRESS}, as expected."
    fi
else
    log_warn "⚠️ Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
