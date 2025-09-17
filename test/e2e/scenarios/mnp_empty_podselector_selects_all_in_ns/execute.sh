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
NAMESPACE_FILE="${SCENARIO_DIR}/01_ns_for_empty_selector_test.yaml"
POD_A_FILE="${SCENARIO_DIR}/02_pod_a_in_ns_empty.yaml"
POD_B_FILE="${SCENARIO_DIR}/03_pod_b_in_ns_empty.yaml"
POD_C_OTHER_NS_FILE="${SCENARIO_DIR}/04_pod_c_in_other_ns.yaml" # Pod in different namespace
MNP_FILE="${SCENARIO_DIR}/05_mnp_empty_podselector.yaml"

TARGET_NAMESPACE="ns-for-empty-selector-test"
POD_A_NAME="pod-a-in-ns-empty"
POD_B_NAME="pod-b-in-ns-empty"
POD_C_NAME="pod-c-in-other-ns" # Pod name in 'default' namespace
POD_C_NAMESPACE="default"     # Pod C namespace

MNP_NAME="policy-empty-selector"
MNP_NAMESPACE="${TARGET_NAMESPACE}" # MNP is in the same namespace as pods A and B

NAD_NAME_IN_MANIFEST="e2e-test-bridge"
NAD_NAMESPACE_IN_MANIFEST="default" # NAD is in the default namespace

POLICY_FOR_NAD_NAME="${NAD_NAME_IN_MANIFEST}"
POLICY_FOR_NAD_NAMESPACE_REF="${NAD_NAMESPACE_IN_MANIFEST}"

NFT_CONTROLLER_NAMESPACE="kube-system"
NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"

POD_A_MAC_GLOBAL=""
POD_B_MAC_GLOBAL=""
POD_C_MAC_GLOBAL="" # MAC of pod C

EXPECTED_CHAIN_SUFFIX_POD_A_GLOBAL=""
EXPECTED_CHAIN_SUFFIX_POD_B_GLOBAL=""
# We do not expect chain to Pod C from this MNP

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
    ${KUBECTL} delete --ignore-not-found=true -f "${POD_A_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${POD_B_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${POD_C_OTHER_NS_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NAMESPACE_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"

    log_info "  Waiting for controller to process deletions (30s)..."
    sleep 30

    log_info "  Checking if ruleset is clean after cleanup..."
    KIND_CONTROL_PLANE_ID_CLEANUP=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
    if [[ -n "$KIND_CONTROL_PLANE_ID_CLEANUP" ]]; then
        log_info "  Waiting a bit more for reconciler (10s)..."
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
        # Check for absence of jumps to the MACs of pods A and B
        if [[ -n "$POD_A_MAC_GLOBAL" ]] && echo "$FINAL_RULESET" | grep -q "ether daddr ${POD_A_MAC_GLOBAL} jump"; then
            log_error "❌ CLEANUP ERROR: JUMP Ingress rule for POD A's MAC (${POD_A_MAC_GLOBAL}) still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
         if [[ -n "$POD_B_MAC_GLOBAL" ]] && echo "$FINAL_RULESET" | grep -q "ether daddr ${POD_B_MAC_GLOBAL} jump"; then
            log_error "❌ CLEANUP ERROR: JUMP Ingress rule for POD B's MAC (${POD_B_MAC_GLOBAL}) still exists!"
            ERROR_FOUND_CLEANUP=1
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

verify_ingress_rules_for_pod() {
    local state_label="$1"
    local pod_mac="$2"
    local expected_chain_name="$3"
    local expected_cidr_param="$4"
    local expected_port="$5" # Can be a comma separated list
    local pod_label_for_log="$6"

    log_info "🔎 ${state_label} Checking JUMP Ingress for MAC ${pod_mac} for ${expected_chain_name} (${pod_label_for_log})..."
    JUMP_RULE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
        grep -F "ether daddr ${pod_mac} jump ${expected_chain_name}" || echo "NOT_FOUND")
    if [[ "$JUMP_RULE_OUTPUT" == "NOT_FOUND" ]]
    then
        log_error "❌ ${state_label} JUMP Ingress rule for MAC ${pod_mac} for ${expected_chain_name} (${pod_label_for_log}) NOT found."
        ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
        return 1
    fi
    log_success "✔️ ${state_label} JUMP Ingress rule for ${expected_chain_name} (${pod_label_for_log}) found."

    log_info "🔎 ${state_label} Checking if the chain ${expected_chain_name} (${pod_label_for_log}) exists..."
    if ! ${EXEC_KIND} nft list chain bridge filter "${expected_chain_name}" > /dev/null 2>&1; then
        log_error "❌ ${state_label} Chain Ingress ${expected_chain_name} (${pod_label_for_log}) NOT found."
        return 1
    fi
    log_success "✔️ ${state_label} Chain Ingress ${expected_chain_name} (${pod_label_for_log}) found."

    log_info "🔎 ${state_label} Checking rules inside chain ${expected_chain_name} (${pod_label_for_log})..."
    INGRESS_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${expected_chain_name}")

    IP_FOR_SET_CHECK="${expected_cidr_param%%/*}"
    IS_SINGLE_IP=false
    if [[ "$expected_cidr_param" == *"/"* ]]
    then
        MASK_PART="${expected_cidr_param#*/}"
        if [[ "$MASK_PART" == "32" ]]
        then
            IS_SINGLE_IP=true
        fi
    else
        IS_SINGLE_IP=true; IP_FOR_SET_CHECK="$expected_cidr_param"
    fi

    RULE_LINE=""
    if [[ "$IS_SINGLE_IP" == true ]]
    then
        RULE_LINE=$(echo "$INGRESS_CHAIN_RULES" | grep "ip saddr @mnp-src-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    else
        RULE_LINE=$(echo "$INGRESS_CHAIN_RULES" | grep -F "ip saddr ${expected_cidr_param}" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    fi

    if [[ -z "$RULE_LINE" ]]
    then
        log_error "❌ ${state_label} Ingress rule (Expected: ${expected_cidr_param} -> TCP Port Set) not found in chain ${expected_chain_name} (${pod_label_for_log})."
        echo "$INGRESS_CHAIN_RULES"
        return 1
    fi

    TCP_PORT_SET_NAME=$(echo "$RULE_LINE" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
    if [[ -z "$TCP_PORT_SET_NAME" ]]
    then
        log_error "❌ ${state_label} Failed to fetch TCP Ingress port set name for ${pod_label_for_log}."
        return 1
    fi
    
    # Check each expected port
    IFS=',' read -ra PORTS_TO_CHECK <<< "$expected_port"
    for port_check in "${PORTS_TO_CHECK[@]}"
    do
        ${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME}" | grep -qE "(^|[[:space:],{])${port_check}([[:space:],}]|$)" || \
            { log_error "❌ ${state_label} Set Ingress ${TCP_PORT_SET_NAME} does not contain port ${port_check} for ${pod_label_for_log}."; return 1; }
    done


    if [[ "$IS_SINGLE_IP" == true ]]
    then
        SRC_IP_SET_NAME=$(echo "$RULE_LINE" | grep -o 'mnp-src-ip-[a-f0-9]\{16\}' | head -n1)
        if [[ -z "$SRC_IP_SET_NAME" ]]
        then
            log_error "❌ ${state_label} Failed to fetch Ingress source IP set name for ${pod_label_for_log}."
            return 1
        fi
        ${EXEC_KIND} nft list set bridge filter "${SRC_IP_SET_NAME}" | grep -qF "${IP_FOR_SET_CHECK}" || \
            { log_error "❌ ${state_label} Set Ingress ${SRC_IP_SET_NAME} does not contain ${IP_FOR_SET_CHECK} for ${pod_label_for_log}."; return 1; }
    fi
    log_success "✔️ ${state_label} Ingress rules and sets checked for ${pod_label_for_log}."
    return 0
}

verify_NO_ingress_rules_for_pod() {
    local pod_mac="$1"
    local pod_label_for_log="$2"
    # In this case, we don't know the name of the chain if it shouldn't be created,
    # so we just check for the absence of a jump to the MAC.
    log_info "🔎 Checking for ABSENCE of JUMP Ingress for MAC ${pod_mac} (${pod_label_for_log})..."
    JUMP_RULE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
        grep -F "ether daddr ${pod_mac} jump KUBE_MULTI_INGRESS_" || echo "NOT_FOUND") # Search for any chain with the prefix
    if [[ "$JUMP_RULE_OUTPUT" != "NOT_FOUND" ]]
    then
        log_error "❌ JUMP Ingress rule for MAC ${pod_mac} (${pod_label_for_log}) WAS found, but it shouldn't have been."
        echo "Rule found: $JUMP_RULE_OUTPUT"
        return 1
    fi
    log_success "✔️ No JUMP Ingress rule for MAC ${pod_mac} (${pod_label_for_log}) found, as expected."
    return 0
}


TEST_NAME=$(cat "${SCENARIO_DIR}/test.def")

log_info "🚀 Starting E2E Test: ${TEST_NAME}"

# 1. Initial Setup
${KUBECTL} apply -f "${NAD_FILE}"
${KUBECTL} apply -f "${NAMESPACE_FILE}"
${KUBECTL} apply -f "${POD_A_FILE}"
${KUBECTL} apply -f "${POD_B_FILE}"
${KUBECTL} apply -f "${POD_C_OTHER_NS_FILE}" # Pod in different namespace

log_info "⏳ Waiting for pod ${POD_A_NAME} in ${TARGETNAMESPACE} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${POD_A_NAME}" -n "${TARGET_NAMESPACE}" --timeout=180s
POD_A_MAC_GLOBAL=$(get_pod_mac "${POD_A_NAME}" "${TARGET_NAMESPACE}")
if [[ -z "$POD_A_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${POD_A_NAME} not found."
    exit 1
fi

log_info "⏳ Waiting for pod ${POD_B_NAME} in ${TARGETNAMESPACE} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${POD_B_NAME}" -n "${TARGET_NAMESPACE}" --timeout=180s
POD_B_MAC_GLOBAL=$(get_pod_mac "${POD_B_NAME}" "${TARGET_NAMESPACE}")
if [[ -z "$POD_B_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${POD_B_NAME} not found."
    exit 1
fi

log_info "⏳ Waiting for pod ${POD_C_NAME} in ${POD_C_NAMESPACE} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${POD_C_NAME}" -n "${POD_C_NAMESPACE}" --timeout=180s
POD_C_MAC_GLOBAL=$(get_pod_mac "${POD_C_NAME}" "${POD_C_NAMESPACE}")
if [[ -z "$POD_C_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${POD_C_NAME} not found."
    exit 1
fi

log_info "🔩 Applying MultiNetworkPolicy with empty podSelector: ${MNP_FILE}"
${KUBECTL} apply -f "${MNP_FILE}"

log_info "⏳ Waiting for mnp-nft-bridge controller to apply state (45 seconds)..."
sleep 45

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Could not get Kind's control-plane ID."
    exit 1
fi

# Generate suffixes and chain names for Pod A and Pod B
EXPECTED_CHAIN_SUFFIX_POD_A_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${TARGET_NAMESPACE}" "${POD_A_NAME}")
EXPECTED_INGRESS_CHAIN_POD_A_GLOBAL="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_POD_A_GLOBAL}"

EXPECTED_CHAIN_SUFFIX_POD_B_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${TARGET_NAMESPACE}" "${POD_B_NAME}")
EXPECTED_INGRESS_CHAIN_POD_B_GLOBAL="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_POD_B_GLOBAL}"

# MultiNetworkPolicy Rule Details
INGRESS_CIDR_FROM_MNP="192.168.200.0/24" # This is a range, it will result in a mask rule
INGRESS_PORTS_FROM_MNP="80,8080"         # Multiple ports

log_info "🔎 === Checking Applied Rules (MultiNetworkPolicy with empty podSelector) ==="
# Check Pod A (must be selected)
log_info "🔎 Checking rules for Pod A (${POD_A_NAME})..."
verify_ingress_rules_for_pod "[PodA]" "${POD_A_MAC_GLOBAL}" "${EXPECTED_INGRESS_CHAIN_POD_A_GLOBAL}" \
    "${INGRESS_CIDR_FROM_MNP}" "${INGRESS_PORTS_FROM_MNP}" "${POD_A_NAME}" || exit 1

# Check Pod B (must be selected)
log_info "🔎 Checking rules for Pod B (${POD_B_NAME})..."
verify_ingress_rules_for_pod "[PodB]" "${POD_B_MAC_GLOBAL}" "${EXPECTED_INGRESS_CHAIN_POD_B_GLOBAL}" \
    "${INGRESS_CIDR_FROM_MNP}" "${INGRESS_PORTS_FROM_MNP}" "${POD_B_NAME}" || exit 1

# Check Pod C (should NOT be selected as it is in another namespace)
log_info "🔎 Checking for MISSING rules for Pod C (${POD_C_NAME} in namespace ${POD_C_NAMESPACE})..."
verify_NO_ingress_rules_for_pod "${POD_C_MAC_GLOBAL}" "${POD_C_NAME}" || exit 1

log_success "✔️ [Main Check] nftables state for MNP with empty podSelector checked successfully."

# Check NftPodChainMetadataCache for Pod A and Pod B
CONTROLLER_POD_NAME_LOGS=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME_LOGS" ]]
then
    log_info "🔎 Checking NftPodChainMetadataCache..."
    LOG_SINCE_DURATION="10m"; sleep 5 

    # Pod A
    EXPECTED_CACHE_KEY_POD_A="${EXPECTED_CHAIN_SUFFIX_POD_A_GLOBAL}_ingress"
    log_info "   Looking for Pod A cache key: ${EXPECTED_CACHE_KEY_POD_A} with PolicyName: ${MNP_NAMESPACE}/${MNP_NAME}, PolicyIngressRuleCount: 1, IsIsolationChain:false"
    ALL_POD_A_CACHE_LOGS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_LOGS}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION} | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_POD_A}")
    LATEST_VALID_POD_A_LOG=$(echo "$ALL_POD_A_CACHE_LOGS" | grep "Added/Updated" | \
        grep "PolicyName: ${MNP_NAMESPACE}/${MNP_NAME}" | grep "PolicyIngressRuleCount: 1" | grep "IsIsolationChain:false" | tail -n 1 || echo "")
    if [[ -z "$LATEST_VALID_POD_A_LOG" ]]
    then 
        log_error "❌ Cache entry for Pod A (key ${EXPECTED_CACHE_KEY_POD_A}) missing or incorrect."
        echo "Logs for Pod A key (${EXPECTED_CACHE_KEY_POD_A}):"
        echo "${ALL_POD_A_CACHE_LOGS:- (No log)}"
        exit 1; 
    fi
    log_success "✔️ Cache entry for Pod A found."

    # Pod B
    EXPECTED_CACHE_KEY_POD_B="${EXPECTED_CHAIN_SUFFIX_POD_B_GLOBAL}_ingress"
    log_info "   Looking for Pod B cache key: ${EXPECTED_CACHE_KEY_POD_B} with PolicyName: ${MNP_NAMESPACE}/${MNP_NAME}, PolicyIngressRuleCount: 1, IsIsolationChain:false"
    ALL_POD_B_CACHE_LOGS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_LOGS}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION} | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_POD_B}")
    LATEST_VALID_POD_B_LOG=$(echo "$ALL_POD_B_CACHE_LOGS" | grep "Added/Updated" | \
        grep "PolicyName: ${MNP_NAMESPACE}/${MNP_NAME}" | grep "PolicyIngressRuleCount: 1" | grep "IsIsolationChain:false" | tail -n 1 || echo "")
    if [[ -z "$LATEST_VALID_POD_B_LOG" ]]
    then 
        log_error "❌ Cache entry for Pod B (key ${EXPECTED_CACHE_KEY_POD_B}) missing or incorrect."
        echo "Logs for Pod B key (${EXPECTED_CACHE_KEY_POD_B}):"
        echo "${ALL_POD_B_CACHE_LOGS:- (no log)}"
        exit 1; 
    fi
    log_success "✔️ Cache entry for Pod B found."

    # Pod C (should not have entry for this MultiNetworkPolicy)
    EXPECTED_CHAIN_SUFFIX_POD_C_POTENTIAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${POD_C_NAMESPACE}" "${POD_C_NAME}")
    EXPECTED_CACHE_KEY_POD_C_ABSENT="${EXPECTED_CHAIN_SUFFIX_POD_C_POTENTIAL}_ingress"
    log_info "   Checking for ABSENCE of cache key for Pod C: ${EXPECTED_CACHE_KEY_POD_C_ABSENT} (related to this MultiNetworkPolicy)"
    ABSENT_POD_C_CACHE_LOG=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_LOGS}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION} | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_POD_C_ABSENT}" || echo "KEY_NOT_FOUND")
    if [[ "$ABSENT_POD_C_CACHE_LOG" != "KEY_NOT_FOUND" ]]
    then
        log_error "❌ Cache entry for Pod C (key ${EXPECTED_CACHE_KEY_POD_C_ABSENT}) WAS found, but it shouldn't have been."
        echo "Log found: $ABSENT_POD_C_CACHE_LOG"
        exit 1
    fi
    log_success "✔️ No Cache entry for Pod C (key ${EXPECTED_CACHE_KEY_POD_C_ABSENT}) found, as expected."

else
    log_warn "⚠️ Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
