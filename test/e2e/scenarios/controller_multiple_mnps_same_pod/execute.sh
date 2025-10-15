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
SHARED_POD_FILE="${SCENARIO_DIR}/01_shared_pod_multiple_mnps.yaml"
MNP_ALPHA_FILE="${SCENARIO_DIR}/02_mnp_policy_alpha.yaml"
MNP_BETA_FILE="${SCENARIO_DIR}/03_mnp_policy_beta.yaml"

SHARED_POD_NAME="shared-pod-multiple-mnps"
POD_NAMESPACE="default"

MNP_ALPHA_NAME="mnp-policy-alpha"
MNP_BETA_NAME="mnp-policy-beta"
MNP_NAMESPACE="default"

NAD_NAME_IN_MANIFEST="e2e-test-bridge"
NAD_NAMESPACE_IN_MANIFEST="default"

NFT_CONTROLLER_NAMESPACE="kube-system"
NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"

SHARED_POD_MAC_GLOBAL=""
EXPECTED_CHAIN_SUFFIX_ALPHA_GLOBAL=""
EXPECTED_CHAIN_SUFFIX_BETA_GLOBAL=""
EXPECTED_INGRESS_CHAIN_ALPHA_GLOBAL=""
EXPECTED_INGRESS_CHAIN_BETA_GLOBAL=""


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

    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_ALPHA_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_BETA_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${SHARED_POD_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"

    log_info "  Waiting for controller to process deletions (30s)..."
    sleep 30

    log_info "  Checking if ruleset is clean after cleanup..."
    KIND_CONTROL_PLANE_ID_CLEANUP=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
    if [[ -n "$KIND_CONTROL_PLANE_ID_CLEANUP" ]]; then
        log_info "  Waiting a little longer for the reconciler (10s)..."
        sleep 10
        FINAL_RULESET=$(${EXEC_KIND} nft list ruleset bridge)

        ERROR_FOUND_CLEANUP=0
        if [[ -n "$EXPECTED_INGRESS_CHAIN_ALPHA_GLOBAL" ]] && echo "$FINAL_RULESET" | grep -qF "chain ${EXPECTED_INGRESS_CHAIN_ALPHA_GLOBAL}"; then
            log_error "❌ CLEANUP ERROR: Chain Alpha ${EXPECTED_INGRESS_CHAIN_ALPHA_GLOBAL} still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if [[ -n "$EXPECTED_INGRESS_CHAIN_BETA_GLOBAL" ]] && echo "$FINAL_RULESET" | grep -qF "chain ${EXPECTED_INGRESS_CHAIN_BETA_GLOBAL}"; then
            log_error "❌ CLEANUP ERROR: Beta Chain ${EXPECTED_INGRESS_CHAIN_BETA_GLOBAL} still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -q "set mnp-"; then
            log_error "❌ CLEANUP ERROR: 'mnp-' sets still exist!"
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

verify_specific_mnp_ingress_rules() {
    local state_label="$1"
    local pod_mac="$2"
    local expected_chain_name="$3"
    local expected_cidr="$4"
    local expected_port="$5"
    local mnp_name_for_log="$6"

    log_info "🔎 ${state_label} Checking JUMP Ingress for MAC ${pod_mac} for ${expected_chain_name} (MNP: ${mnp_name_for_log})..."
    JUMP_RULE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
        grep -F "ether daddr ${pod_mac} jump ${expected_chain_name}" || echo "NOT_FOUND")
    if [[ "$JUMP_RULE_OUTPUT" == "NOT_FOUND" ]]
    then
        log_error "❌ ${state_label} JUMP Ingress rule for ${expected_chain_name} (MNP: ${mnp_name_for_log}) NOT found."
        return 1
    fi
    log_success "✔️ ${state_label} JUMP Ingress rule for ${expected_chain_name} (MNP: ${mnp_name_for_log}) found."

    log_info "🔎 ${state_label} Checking if the chain ${expected_chain_name} (MNP: ${mnp_name_for_log}) exists..."
    if ! ${EXEC_KIND} nft list chain bridge filter "${expected_chain_name}" > /dev/null 2>&1; then
        log_error "❌ ${state_label} Chain Ingress ${expected_chain_name} (MNP: ${mnp_name_for_log}) NOT found."; return 1
    fi
    log_success "✔️ ${state_label} Chain Ingress ${expected_chain_name} (MNP: ${mnp_name_for_log}) found."

    log_info "🔎 ${state_label} Checking rules inside chain ${expected_chain_name} (MNP: ${mnp_name_for_log})..."
    INGRESS_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${expected_chain_name}")

    IP_FOR_SET_CHECK="${expected_cidr%%/*}"
    IS_SINGLE_IP=false
    if [[ "$expected_cidr" == *"/"* ]]; then
        MASK_PART="${expected_cidr#*/}"
        if [[ "$MASK_PART" == "32" ]]
        then
            IS_SINGLE_IP=true
        fi
    else
        IS_SINGLE_IP=true
        IP_FOR_SET_CHECK="$expected_cidr"
    fi

    RULE_LINE=""
    if [[ "$IS_SINGLE_IP" == true ]]
    then
        RULE_LINE=$(echo "$INGRESS_CHAIN_RULES" | grep "ip saddr @mnp-src-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    else
        RULE_LINE=$(echo "$INGRESS_CHAIN_RULES" | grep -F "ip saddr ${expected_cidr}" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    fi

    if [[ -z "$RULE_LINE" ]]
    then
        log_error "❌ ${state_label} Ingress rule (CIDR/IP ${expected_cidr} -> TCP Port Set) for MNP ${mnp_name_for_log} not found."
        echo "$INGRESS_CHAIN_RULES"
        return 1
    fi

    TCP_PORT_SET_NAME=$(echo "$RULE_LINE" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
    if [[ -z "$TCP_PORT_SET_NAME" ]]
    then
        log_error "❌ ${state_label} Failed to extract TCP Ingress port set name for MNP ${mnp_name_for_log}."
        return 1
    fi
    ${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME}" | grep -qE "(^|[[:space:],{])${expected_port}([[:space:],}]|$)" || \
        { log_error "❌ ${state_label} Set Ingress ${TCP_PORT_SET_NAME} for MNP ${mnp_name_for_log} does not contain port ${expected_port}."; return 1; }

    if [[ "$IS_SINGLE_IP" == true ]]
    then
        SRC_IP_SET_NAME=$(echo "$RULE_LINE" | grep -o 'mnp-src-ip-[a-f0-9]\{16\}' | head -n1)
        if [[ -z "$SRC_IP_SET_NAME" ]]
        then
            log_error "❌ ${state_label} Failed to extract name from Ingress source IP set for MNP ${mnp_name_for_log}."
            return 1
        fi
        ${EXEC_KIND} nft list set bridge filter "${SRC_IP_SET_NAME}" | grep -qF "${IP_FOR_SET_CHECK}" || \
            { log_error "❌ ${state_label} Set Ingress ${SRC_IP_SET_NAME} does not contain ${IP_FOR_SET_CHECK}."; return 1; }
    fi
    log_success "✔️ ${state_label} Ingress rules and sets for MNP ${mnp_name_for_log} checked."
    return 0
}


TEST_NAME=$(cat "${SCENARIO_DIR}/test.def")

log_info "🚀 Starting E2E Test: ${TEST_NAME}"

# 1. Initial Setup
${KUBECTL} apply -f "${NAD_FILE}"
${KUBECTL} apply -f "${SHARED_POD_FILE}"
${KUBECTL} apply -f "${MNP_ALPHA_FILE}"
${KUBECTL} apply -f "${MNP_BETA_FILE}"

log_info "⏳ Waiting for pod ${SHARED_POD_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${SHARED_POD_NAME}" -n "${POD_NAMESPACE}" --timeout=240s
SHARED_POD_MAC_GLOBAL=$(get_pod_mac "${SHARED_POD_NAME}" "${POD_NAMESPACE}")
if [[ -z "$SHARED_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${SHARED_POD_NAME} not found."
    exit 1
fi

log_info "⏳ Waiting for mnp-nft-bridge controller to apply initial state (45 seconds)..."
sleep 45

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Could not get Kind's control-plane ID."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX_ALPHA_GLOBAL=$(generate_pod_chain_suffix "${MNP_ALPHA_NAME}" "${MNP_NAMESPACE}" "${POD_NAMESPACE}" "${SHARED_POD_NAME}")
EXPECTED_INGRESS_CHAIN_ALPHA_GLOBAL="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_ALPHA_GLOBAL}"

EXPECTED_CHAIN_SUFFIX_BETA_GLOBAL=$(generate_pod_chain_suffix "${MNP_BETA_NAME}" "${MNP_NAMESPACE}" "${POD_NAMESPACE}" "${SHARED_POD_NAME}")
EXPECTED_INGRESS_CHAIN_BETA_GLOBAL="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_BETA_GLOBAL}"

INGRESS_CIDR_ALPHA="192.168.1.10/32"
INGRESS_PORT_ALPHA="80"
INGRESS_CIDR_BETA="192.168.1.20/32"
INGRESS_PORT_BETA="8080"

log_info "🔎 === Checking Initial State (Both MNPs Applied to the Same Pod) ==="
verify_specific_mnp_ingress_rules "[Initial-Alpha]" "${SHARED_POD_MAC_GLOBAL}" "${EXPECTED_INGRESS_CHAIN_ALPHA_GLOBAL}" \
    "${INGRESS_CIDR_ALPHA}" "${INGRESS_PORT_ALPHA}" "${MNP_ALPHA_NAME}" || exit 1
verify_specific_mnp_ingress_rules "[Initial-Beta]" "${SHARED_POD_MAC_GLOBAL}" "${EXPECTED_INGRESS_CHAIN_BETA_GLOBAL}" \
    "${INGRESS_CIDR_BETA}" "${INGRESS_PORT_BETA}" "${MNP_BETA_NAME}" || exit 1

log_info "🔎 [Initial] Checking PRESENCE of DROP Ingress rule for MAC ${SHARED_POD_MAC_GLOBAL} in chain KUBE_MULTI_INGRESS..."
DROP_RULE_INGRESS_BASE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${SHARED_POD_MAC_GLOBAL} drop" || echo "NOT_FOUND")
if [[ "$DROP_RULE_INGRESS_BASE_OUTPUT" == "NOT_FOUND" ]]
then
    log_error "❌ [Initial] MAC-specific DROP Ingress rule ${SHARED_POD_MAC_GLOBAL} NOT found in KUBE_MULTI_INGRESS, but should be."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
    exit 1
fi
log_success "✔️ [Initial] Specific DROP Ingress rule for MAC ${SHARED_POD_MAC_GLOBAL} found in KUBE_MULTI_INGRESS, as expected."

log_success "✔️ [Inicial] Initial nftables state for multiple MNPs verified successfully."

# Check NftPodChainMetadataCache
CONTROLLER_POD_NAME_LOGS=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME_LOGS" ]]; then
    log_info "🔎 [Initial] Checking NftPodChainMetadataCache for both policies..."
    # Fetch all relevant logs in one go
    ALL_CACHE_LOGS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_LOGS}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" || echo "NO_CACHE_LOGS")

    # Check for MNP Alpha
    EXPECTED_CACHE_KEY_ALPHA="${EXPECTED_CHAIN_SUFFIX_ALPHA_GLOBAL}_ingress"

    log_info "   --> Verifying cache entry for MNP Alpha (key: ${EXPECTED_CACHE_KEY_ALPHA})"
    CACHE_LOG_ALPHA=$(echo "$ALL_CACHE_LOGS" | grep "for key: ${EXPECTED_CACHE_KEY_ALPHA}" | \
        grep "PolicyIngressRuleCount: 1" | grep "PolicyName: ${MNP_NAMESPACE}/${MNP_ALPHA_NAME}" | grep "IsIsolationChain:false" | tail -n 1 || echo "")

    if [[ -z "$CACHE_LOG_ALPHA" ]]
    then
        log_error "❌ [Initial] Cache Ingress entry for MNP Alpha (key ${EXPECTED_CACHE_KEY_ALPHA}) missing or incorrect."
        echo "Relevant logs captured:"
        echo "$ALL_CACHE_LOGS"        
        exit 1
    fi
    log_success "✔️ [Initial] Cache Ingress entry for MNP Alpha found and correct."

    # Check for MNP Beta
    EXPECTED_CACHE_KEY_BETA="${EXPECTED_CHAIN_SUFFIX_BETA_GLOBAL}_ingress"

    log_info "   --> Verifying cache entry for MNP Beta (key: ${EXPECTED_CACHE_KEY_BETA})"
    CACHE_LOG_BETA=$(echo "$ALL_CACHE_LOGS" | grep "for key: ${EXPECTED_CACHE_KEY_BETA}" | \
        grep "PolicyIngressRuleCount: 1" | grep "PolicyName: ${MNP_NAMESPACE}/${MNP_BETA_NAME}" | grep "IsIsolationChain:false" | tail -n 1 || echo "")

    if [[ -z "$CACHE_LOG_BETA" ]]
    then
        log_error "❌ [Initial] Cache Ingress entry for MNP Beta (key ${EXPECTED_CACHE_KEY_BETA}) missing or incorrect."
        echo "Relevant logs captured:"
        echo "$ALL_CACHE_LOGS"        
        exit 1
    fi
    log_success "✔️ [Initial] Cache Ingress entry for MNP Beta found and correct."
else
    log_warn "⚠️ [Initial] Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
