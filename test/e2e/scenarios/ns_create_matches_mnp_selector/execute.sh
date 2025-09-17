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
NS_TARGET_FILE="${SCENARIO_DIR}/01_ns_target_for_ns_test.yaml"
TARGET_POD_FILE="${SCENARIO_DIR}/02_target_pod_in_ns_target.yaml"
MNP_FILE="${SCENARIO_DIR}/03_mnp_allow_from_client_ns.yaml"
# NS_NEW_CLIENT_FILE will be applied LATER as part of the ACTION
CLIENT_POD_IN_NEW_NS_FILE="${SCENARIO_DIR}/05_client_pod_in_ns_new.yaml" 

TARGET_POD_NAME="target-pod-in-ns-target"
TARGET_POD_NAMESPACE="ns-target-for-ns-test" 

CLIENT_POD_NAME="client-pod-in-ns-new"
CLIENT_POD_NEW_NAMESPACE="ns-new-client" # Namespace to be created/labeled

MNP_NAME="policy-allow-from-client-ns" 
MNP_NAMESPACE="ns-target-for-ns-test" # MultiNetworkPolicy is in the target pod's namespace

POLICY_FOR_NAD_NAME="e2e-test-bridge"
POLICY_FOR_NAD_NAMESPACE_REF="default" # NetworkAttachmentDefinition is in the default namespace

NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"

TARGET_POD_MAC_GLOBAL=""
CLIENT_POD_MAC_GLOBAL=""
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
    ${KUBECTL} delete --ignore-not-found=true -f "${CLIENT_POD_IN_NEW_NS_FILE}"
    # The ns-new-client namespace is created by the test, so it needs to be deleted.
    # The 04_ns_new_client_with_label.yaml file defines this namespace.
    ${KUBECTL} delete --ignore-not-found=true -f "${SCENARIO_DIR}/04_ns_new_client_with_label.yaml"
    
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_FILE}"
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

# 1. Initial Setup: Apply NAD, Target NS, Target Pod, and MNP.
# The Client Pod and its Namespace (ns-new-client) will be created LATER.
${KUBECTL} apply -f "${NAD_FILE}"
${KUBECTL} apply -f "${NS_TARGET_FILE}"
${KUBECTL} apply -f "${TARGET_POD_FILE}"

log_info "⏳ Waiting for pod ${TARGET_POD_NAME} in ${TARGET_POD_NAMESPACE} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${TARGET_POD_NAMESPACE}" --timeout=180s
TARGET_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${TARGET_POD_NAMESPACE}")
if [[ -z "$TARGET_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${TARGET_POD_NAME} not found."
    exit 1
fi

log_info "🔩 Applying MNP (with namespaceSelector env=client): ${MNP_FILE}"
${KUBECTL} apply -f "${MNP_FILE}"

log_info "⏳ Waiting for controller to process MNP and Pod Target (20 seconds)..."
sleep 20

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Could not get Kind's control-plane ID."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${TARGET_POD_NAMESPACE}" "${TARGET_POD_NAME}")
EXPECTED_INGRESS_CHAIN_NAME="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"

log_info "🔎 === Checking Initial State (Before Creating Client Namespace and Client Pod) ==="
log_info "🔎 [Initial] Checking JUMP Ingress for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME}..."
JUMP_RULE_INGRESS_INITIAL=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME}" || echo "")
if [[ -z "$JUMP_RULE_INGRESS_INITIAL" ]]
then
    log_error "❌ [Initial] JUMP Ingress rule NOT found."
    exit 1
fi
log_success "✔️ [Initial] JUMP Ingress rule found."

log_info "🔎 [Initial] Checking contents of chain ${EXPECTED_INGRESS_CHAIN_NAME} (must be empty or without MAC rules yet)..."
INGRESS_POD_CHAIN_RULES_INITIAL=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}")
# The chain must exist, but the mnp-src-mac- set for this namespaceSelector rule must be empty or not yet exist.
# If the set is created empty, the lookup rule will have no effect.
# Let's check if the mnp-src-mac set (if it exists for this rule) is empty.
# The set name is deterministic: mnp-<type>-<chainSuffix_ruleDirection_ruleIndex_setType>
# For the first ingress rule (index 0) with namespaceSelector, we expect an mnp-src-mac set.
SRC_MAC_SET_NAME_PATTERN="mnp-src-mac-${EXPECTED_CHAIN_SUFFIX_GLOBAL:0:8}" # Use part of the chain suffix for the set ID

# Check if the source MAC set for this rule is empty or contains no MACs yet
log_info "🔎 [Initial] Checking if the source MAC set (if exists) is empty..."
SET_LIST_OUTPUT=$(${EXEC_KIND} nft list sets bridge filter 2>/dev/null || echo "NO_SETS_OR_ERROR")
if echo "$SET_LIST_OUTPUT" | grep -q "$SRC_MAC_SET_NAME_PATTERN"; then
    MAC_SET_CONTENT=$(${EXEC_KIND} nft list set bridge filter "mnp-src-mac-$(echo "$INGRESS_POD_CHAIN_RULES_INITIAL" | grep -o 'mnp-src-mac-[a-f0-9]\{16\}' | head -n1)" 2>/dev/null || echo "SET_ERROR")
    if [[ "$MAC_SET_CONTENT" != "SET_ERROR" ]] && echo "$MAC_SET_CONTENT" | grep -q "elements = { }"; then
        log_success "✔️ [Initial] Source MAC set found and is empty as expected."
    elif [[ "$MAC_SET_CONTENT" == "SET_ERROR" ]] && ! echo "$INGRESS_POD_CHAIN_RULES_INITIAL" | grep -q "@mnp-src-mac-"; then
         log_success "✔️ [Initial] Source MAC set does not exist yet (no rule references it), as expected."
    elif [[ "$MAC_SET_CONTENT" != "SET_ERROR" ]]; then
        log_warn "⚠️ [Initial] Source MAC set exists but is not empty: $MAC_SET_CONTENT"
        # This might be OK if other rules in the same chain use the same set, but for this test, we expect it to be empty initially.
    fi
else
    log_success "✔️ [Initial] No source MAC set with pattern ${SRC_MAC_SET_NAME_PATTERN} found, as expected."
fi


# 2. Action: Create the Client Namespace with the correct label and the Client Pod within it
log_info "🔩 Creating Client Namespace (${CLIENT_POD_NEW_NAMESPACE}) with label env=client: ${SCENARIO_DIR}/04_ns_new_client_with_label.yaml"
${KUBECTL} apply -f "${SCENARIO_DIR}/04_ns_new_client_with_label.yaml"
log_info "🔩 Creating Client Pod in ${CLIENT_POD_NEW_NAMESPACE}: ${CLIENT_POD_IN_NEW_NS_FILE}"
${KUBECTL} apply -f "${CLIENT_POD_IN_NEW_NS_FILE}"

log_info "⏳ Waiting for pod ${CLIENT_POD_NAME} in ${CLIENT_POD_NEW_NAMESPACE} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${CLIENT_POD_NAME}" -n "${CLIENT_POD_NEW_NAMESPACE}" --timeout=180s
CLIENT_POD_MAC_GLOBAL=$(get_pod_mac "${CLIENT_POD_NAME}" "${CLIENT_POD_NEW_NAMESPACE}")
if [[ -z "$CLIENT_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${CLIENT_POD_NAME} not found."
    exit 1
fi

log_info "⏳ Waiting for controller to process NS and Client Pod creation (30 seconds)..."
sleep 30

# 3. Post-Creation Checks of Namespace and Client Pod
log_info "🔎 === Checking Status After Creating the Client Namespace and Client Pod ==="
log_info "🔎 [Post-Create Namespace] Checking rules within chain ${EXPECTED_INGRESS_CHAIN_NAME} for Target Pod..."
INGRESS_POD_CHAIN_RULES_UPDATED=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}")

# The MultiNetworkPolicy has a rule: from namespaceSelector{env=client}, ports TCP/80
# We expect a rule: ether saddr @<set_de_macs_do_ns_client> tcp dport @<set_de_porta_80> accept
EXPECTED_PORT_MNP="80"

RULE_LINE_UPDATED=$(echo "$INGRESS_POD_CHAIN_RULES_UPDATED" | grep "ether saddr @mnp-src-mac-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
if [[ -z "$RULE_LINE_UPDATED" ]]
then
    log_error "❌ [Post-Create Namespace] Ingress rule (MAC Set -> TCP Port Set) not found in chain ${EXPECTED_INGRESS_CHAIN_NAME}."
    echo "$INGRESS_POD_CHAIN_RULES_UPDATED"
    exit 1
fi

SRC_MAC_SET_NAME_UPDATED=$(echo "$RULE_LINE_UPDATED" | grep -o 'mnp-src-mac-[a-f0-9]\{16\}' | head -n1)
TCP_PORT_SET_NAME_UPDATED=$(echo "$RULE_LINE_UPDATED" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
if [[ -z "$SRC_MAC_SET_NAME_UPDATED" || -z "$TCP_PORT_SET_NAME_UPDATED" ]]
then 
    log_error "❌ [Post-Create Namespace] Failed to extract set names from Ingress rule."
    exit 1; 
fi

log_info "🔎 [Post-Create Namespace] Checking contents of Source MAC Set ${SRC_MAC_SET_NAME_UPDATED}..."
${EXEC_KIND} nft list set bridge filter "${SRC_MAC_SET_NAME_UPDATED}" | grep -qF "${CLIENT_POD_MAC_GLOBAL}" || \
    { log_error "❌ [Post-Create Namespace] Set ${SRC_MAC_SET_NAME_UPDATED} does not contain the Client Pod MAC (${CLIENT_POD_MAC_GLOBAL})."; \
      ${EXEC_KIND} nft list set bridge filter "${SRC_MAC_SET_NAME_UPDATED}"; exit 1; }
log_success "✔️ [Post-Create Namespace] Set ${SRC_MAC_SET_NAME_UPDATED} contains the MAC of the Client Pod."

log_info "🔎 [Post-Create Namespace] Checking contents of TCP Port Set ${TCP_PORT_SET_NAME_UPDATED}..."
${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME_UPDATED}" | grep -qE "(^|[[:space:],{])${EXPECTED_PORT_MNP}([[:space:],}]|$)" || \
    { log_error "❌ [Post-Create Namespace] Set ${TCP_PORT_SET_NAME_UPDATED} does not contain port ${EXPECTED_PORT_MNP}."; \
      ${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME_UPDATED}"; exit 1; }
log_success "✔️ [Post-Create Namespace] Set ${TCP_PORT_SET_NAME_UPDATED} contains the port ${EXPECTED_PORT_MNP}."

# Check NftPodChainMetadataCache (the entry for the target pod must still exist and reflect 1 ingress rule)
CONTROLLER_POD_NAME=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME" ]]
then
    log_info "🔎 [Post-Create Namespace] Checking NftPodChainMetadataCache for ${TARGET_POD_NAME}..."
    EXPECTED_CACHE_KEY_INGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"
    
    # MultiNetworkPolicy still has 1 ingress rule. PolicyEgressRuleCount is 0 because MNP has no egress.
    CACHE_LOG_INGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" | \
        grep "PolicyIngressRuleCount: 1" | grep "PolicyEgressRuleCount: 0" | \
        grep "IsIsolationChain:false" | grep "PolicyRuleCount:1" | tail -n 1 || echo "")
        
    if [[ -z "$CACHE_LOG_INGRESS" ]]
    then
        log_error "❌ [Post-Create Namespace] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} missing or incorrect."
        ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" || echo "(no log for the key)"
        exit 1
    fi
    log_success "✔️ [Post-Create Namespace] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} found and correct."
else
    log_warn "⚠️ [Post-Create Namespace] Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
