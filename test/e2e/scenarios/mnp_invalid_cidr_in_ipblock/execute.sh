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
POD_FILE="${SCENARIO_DIR}/01_target_pod_invalid_cidr_test.yaml"
MNP_FILE="${SCENARIO_DIR}/02_mnp_with_invalid_cidrs.yaml"

TARGET_POD_NAME="target-pod-invalid-cidr-test"
POD_NAMESPACE="default"
MNP_NAME="policy-with-invalid-cidrs"
MNP_NAMESPACE="default"

NAD_NAME_IN_MANIFEST="e2e-test-bridge"
NAD_NAMESPACE_IN_MANIFEST="default"

POLICY_FOR_NAD_NAME="${NAD_NAME_IN_MANIFEST}"
POLICY_FOR_NAD_NAMESPACE_REF="${NAD_NAMESPACE_IN_MANIFEST}"

NFT_CONTROLLER_NAMESPACE="kube-system"
NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"

TARGET_POD_MAC_GLOBAL=""
EXPECTED_CHAIN_SUFFIX_GLOBAL=""
EXPECTED_INGRESS_CHAIN_GLOBAL=""
EXPECTED_EGRESS_CHAIN_GLOBAL=""

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
    ${KUBECTL} delete --ignore-not-found=true -f "${POD_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"

    log_info "  Waiting for controller to process deletions (20s)..."
    sleep 20

    log_info "  Checking if ruleset is clean after cleanup..."
    KIND_CONTROL_PLANE_ID_CLEANUP=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
    if [[ -n "$KIND_CONTROL_PLANE_ID_CLEANUP" ]]; then
        log_info "  Waiting a bit more for reconciler (10s)..."
        sleep 10
        FINAL_RULESET=$(${EXEC_KIND} nft list ruleset bridge)

        ERROR_FOUND_CLEANUP=0
        if [[ -n "$EXPECTED_INGRESS_CHAIN_GLOBAL" ]] && echo "$FINAL_RULESET" | grep -qF "chain ${EXPECTED_INGRESS_CHAIN_GLOBAL}"; then
            log_error "❌ CLEANUP ERROR: Chain Ingress ${EXPECTED_INGRESS_CHAIN_GLOBAL} still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if [[ -n "$EXPECTED_EGRESS_CHAIN_GLOBAL" ]] && echo "$FINAL_RULESET" | grep -qF "chain ${EXPECTED_EGRESS_CHAIN_GLOBAL}"; then
            log_error "❌ CLEANUP ERROR: Chain Egress ${EXPECTED_EGRESS_CHAIN_GLOBAL} still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -q "set mnp-"; then
            log_error "❌ CLEANUP ERROR: Sets 'mnp-' sets still exist!"
            ERROR_FOUND_CLEANUP=1
        fi

        if [[ "$ERROR_FOUND_CLEANUP" -eq 1 ]]
        then
            echo "--- Ruleset Final ---"
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

verify_specific_ingress_rules() {
    local state_label="$1"
    local pod_mac="$2"
    local expected_chain_name="$3"
    local expected_valid_cidr="$4" 
    local expected_port="$5"       

    log_info "🔎 ${state_label} Checking JUMP Ingress for MAC ${pod_mac} for ${expected_chain_name}..."
    JUMP_RULE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
        grep -F "ether daddr ${pod_mac} jump ${expected_chain_name}" || echo "NOT_FOUND")
    if [[ "$JUMP_RULE_OUTPUT" == "NOT_FOUND" ]]
    then
        log_error "❌ ${state_label} JUMP Ingress rule NOT found."
        return 1
    fi
    log_success "✔️ ${state_label} JUMP Ingress rule found."

    log_info "🔎 ${state_label} Checking if chain ${expected_chain_name} exists..."
    if ! ${EXEC_KIND} nft list chain bridge filter "${expected_chain_name}" > /dev/null 2>&1; then
        log_error "❌ ${state_label} Chain Ingress ${expected_chain_name} NOT found."
        return 1
    fi
    log_success "✔️ ${state_label} Chain Ingress ${expected_chain_name} found."

    log_info "🔎 ${state_label} Checking rules within chain ${expected_chain_name} for valid CIDR ${expected_valid_cidr}..."
    INGRESS_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${expected_chain_name}")

    IP_FOR_SET_CHECK="${expected_valid_cidr%%/*}"
    IS_SINGLE_IP=false
    if [[ "$expected_valid_cidr" == *"/"* ]]
    then
        MASK_PART="${expected_valid_cidr#*/}"
        if [[ "$MASK_PART" == "32" ]]
        then
            IS_SINGLE_IP=true
        fi
    else
        IS_SINGLE_IP=true
        IP_FOR_SET_CHECK="$expected_valid_cidr"
    fi

    RULE_LINE=""
    if [[ "$IS_SINGLE_IP" == true ]]
    then
        RULE_LINE=$(echo "$INGRESS_CHAIN_RULES" | grep "ip saddr @mnp-src-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | \
                    grep -E "mnp-src-ip-[0-9a-f]{16}.*mnp-tcp-port-[0-9a-f]{16}") 
    else
        RULE_LINE=$(echo "$INGRESS_CHAIN_RULES" | grep -F "ip saddr ${expected_valid_cidr}" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    fi

    if [[ -z "$RULE_LINE" ]]
    then
        log_error "❌ ${state_label} Ingress rule for valid CIDR ${expected_valid_cidr} -> TCP Port Set not found."
        echo "$INGRESS_CHAIN_RULES"
        return 1
    fi

    TCP_PORT_SET_NAME=$(echo "$RULE_LINE" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
    if [[ -z "$TCP_PORT_SET_NAME" ]]
    then
        log_error "❌ ${state_label} Failed to extract TCP Ingress port set name for valid CIDR."
        return 1
    fi
    ${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME}" | grep -qE "(^|[[:space:],{])${expected_port}([[:space:],}]|$)" || \
        { log_error "❌ ${state_label} Set Ingress ${TCP_PORT_SET_NAME} does not contain port ${expected_port} for valid CIDR."; return 1; }

    if [[ "$IS_SINGLE_IP" == true ]]
    then
        SRC_IP_SET_NAME=$(echo "$RULE_LINE" | grep -o 'mnp-src-ip-[a-f0-9]\{16\}' | head -n1)
        if [[ -z "$SRC_IP_SET_NAME" ]]
        then
            log_error "❌ ${state_label} Failed to extract Ingress source IP set name for valid CIDR."
            return 1
        fi
        ${EXEC_KIND} nft list set bridge filter "${SRC_IP_SET_NAME}" | grep -qF "${IP_FOR_SET_CHECK}" || \
            { log_error "❌ ${state_label} Set Ingress ${SRC_IP_SET_NAME} does not contain ${IP_FOR_SET_CHECK} for valid CIDR."; return 1; }
    fi
    log_success "✔️ ${state_label} Ingress rule for valid CIDR ${expected_valid_cidr} and port ${expected_port} checked."
    return 0
}

verify_specific_egress_rules() {
    local state_label="$1"
    local pod_mac="$2"
    local expected_chain_name="$3"
    local expected_valid_cidr="$4" 
    local expected_port="$5"      

    log_info "🔎 ${state_label} Checking JUMP Egress for MAC ${pod_mac} to ${expected_chain_name}..."
    JUMP_RULE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
        grep -F "ether saddr ${pod_mac} jump ${expected_chain_name}" || echo "NOT_FOUND")
    if [[ "$JUMP_RULE_OUTPUT" == "NOT_FOUND" ]]
    then
        log_error "❌ ${state_label} JUMP Egress rule NOT found."
        return 1
    fi
    log_success "✔️ ${state_label} JUMP Egress rule found."
    
    log_info "🔎 ${state_label} Checking rules within chain ${expected_chain_name} for valid CIDR ${expected_valid_cidr}..."
    EGRESS_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${expected_chain_name}")

    IP_FOR_SET_CHECK="${expected_valid_cidr%%/*}"
    IS_SINGLE_IP=false
    if [[ "$expected_valid_cidr" == *"/"* ]]
    then
        MASK_PART="${expected_valid_cidr#*/}"
        if [[ "$MASK_PART" == "32" ]]
        then
            IS_SINGLE_IP=true
        fi
    else
        IS_SINGLE_IP=true
        IP_FOR_SET_CHECK="$expected_valid_cidr"
    fi

    RULE_LINE=""
    if [[ "$IS_SINGLE_IP" == true ]]
    then
        RULE_LINE=$(echo "$EGRESS_CHAIN_RULES" | grep "ip daddr @mnp-dst-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    else
        RULE_LINE=$(echo "$EGRESS_CHAIN_RULES" | grep -F "ip daddr ${expected_valid_cidr}" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    fi
    if [[ -z "$RULE_LINE" ]]
    then
        log_error "❌ ${state_label} Egress rule for valid CIDR ${expected_valid_cidr} -> TCP Port Set not found."
        echo "$EGRESS_CHAIN_RULES"
        return 1
    fi
    
    TCP_PORT_SET_NAME_EGRESS=$(echo "$RULE_LINE" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
    if [[ -z "$TCP_PORT_SET_NAME_EGRESS" ]]
    then
        log_error "❌ ${state_label} Failed to extract TCP Egress port set name for valid CIDR."
        return 1
    fi
    ${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME_EGRESS}" | grep -qE "(^|[[:space:],{])${expected_port}([[:space:],}]|$)" || \
        { log_error "❌ ${state_label} Set Egress ${TCP_PORT_SET_NAME_EGRESS} does not contain port ${expected_port} for valid CIDR."; return 1; }

    if [[ "$IS_SINGLE_IP" == true ]]
    then
        DST_IP_SET_NAME_EGRESS=$(echo "$RULE_LINE" | grep -o 'mnp-dst-ip-[a-f0-9]\{16\}' | head -n1)
        if [[ -z "$DST_IP_SET_NAME_EGRESS" ]]
        then
            log_error "❌ ${state_label} Failed to extract Egress target IP set name for valid CIDR."
            return 1
        fi
        ${EXEC_KIND} nft list set bridge filter "${DST_IP_SET_NAME_EGRESS}" | grep -qF "${IP_FOR_SET_CHECK}" || \
            { log_error "❌ ${state_label} Set Egress ${DST_IP_SET_NAME_EGRESS} does not contain ${IP_FOR_SET_CHECK} for valid CIDR."; return 1; }
    fi
    log_success "✔️ ${state_label} Egress rule for valid CIDR ${expected_valid_cidr} and port ${expected_port} checked."
    return 0
}


TEST_NAME=$(cat "${SCENARIO_DIR}/test.def")

log_info "🚀 Starting E2E Test: ${TEST_NAME}"

# 1. Initial Setup
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

log_info "⏳ Waiting for mnp-nft-bridge controller to apply state (30 seconds)..."
sleep 30

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Could not get Kind's control-plane ID."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${POD_NAMESPACE}" "${TARGET_POD_NAME}")
EXPECTED_INGRESS_CHAIN_GLOBAL="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"
EXPECTED_EGRESS_CHAIN_GLOBAL="KUBE_MULTI_EGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"

VALID_INGRESS_CIDR="192.168.100.140/32"
VALID_INGRESS_PORT="80" 
VALID_EGRESS_CIDR="10.140.0.0/16"
VALID_EGRESS_PORT="5000"

log_info "🔎 === Checking Applied Rules (Only Valid CIDRs Should Take Effect) ==="
verify_specific_ingress_rules "[Valid-Ingress-Check]" "${TARGET_POD_MAC_GLOBAL}" "${EXPECTED_INGRESS_CHAIN_GLOBAL}" \
    "${VALID_INGRESS_CIDR}" "${VALID_INGRESS_PORT}" || exit 1
log_success "✔️ [Valid-Ingress-Check] Ingress rules for valid CIDR applied correctly."

verify_specific_egress_rules "[Valid-Egress-Check]" "${TARGET_POD_MAC_GLOBAL}" "${EXPECTED_EGRESS_CHAIN_GLOBAL}" \
    "${VALID_EGRESS_CIDR}" "${VALID_EGRESS_PORT}" || exit 1
log_success "✔️ [Valid-Egress-Check] Egress rules for valid CIDR applied correctly."

CONTROLLER_POD_NAME_LOGS=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME_LOGS" ]]
then
    log_info "🔎 Checking controller logs for warnings about invalid CIDRs..."
    LOG_SINCE_DURATION="5m"
    sleep 2 
    
    LOG_OUTPUT_FULL=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_LOGS}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION})
    
    if [[ "$DEBUG_E2E_LOGS" == "true" ]]
    then
        log_info "--- Full Controller Logs (${CONTROLLER_POD_NAME_LOGS}) ---"
        echo "${LOG_OUTPUT_FULL}"
        log_info "--- Full Controller Logs ---"
    fi

    INVALID_CIDR_LOG_COUNT=0
    EXPECTED_INVALID_LOGS=4 

    check_invalid_cidr_log() {
        local cidr_to_check="$1"
        local log_description="$2"
        local found_log_for_this_cidr=false
        
        # Escape for sed (mainly for / and ') and then for grep (ERE metacharacters)
        # This is a simpler escape, focusing on the characters that actually appear and cause problems.
        local sed_escaped_cidr
        sed_escaped_cidr=$(printf '%s\n' "$cidr_to_check" | sed -e "s/'/\\\\'/g" -e 's/\//\\\//g')
        
        # Patterns based on actual log messages, using -F for literal strings where possible
        # and -E for OR. The single quotes are the literal part of the log message.
        log_info "   Checking log for ${log_description} '${cidr_to_check}'"

        # Pattern 1: "Failed to parse CIDR 'THE_CIDR' ... invalid CIDR address: THE_CIDR"
        if echo "${LOG_OUTPUT_FULL}" | grep -i -F "Failed to parse CIDR '${cidr_to_check}'" | grep -i -q -F "invalid CIDR address: ${cidr_to_check}"; then
            found_log_for_this_cidr=true
        # Pattern 2: "Source 'THE_CIDR' is neither a valid CIDR nor a valid single IP"
        elif echo "${LOG_OUTPUT_FULL}" | grep -i -F "Source '${cidr_to_check}'" | grep -i -q "is neither a valid CIDR nor a valid single IP"; then
            found_log_for_this_cidr=true
        # Pattern 3: "Error parsing CIDR 'THE_CIDR' for ... mask rule"
        elif echo "${LOG_OUTPUT_FULL}" | grep -i -F "Error parsing CIDR '${cidr_to_check}'" | grep -i -q "for .* mask rule"; then
            found_log_for_this_cidr=true
        # Pattern 4: "Skipping .* mask rule for invalid CIDR 'THE_CIDR'"
        elif echo "${LOG_OUTPUT_FULL}" | grep -i "Skipping .* mask rule for invalid CIDR" | grep -i -q -F "'${cidr_to_check}'"; then
            found_log_for_this_cidr=true
        fi

        if [[ "$found_log_for_this_cidr" == true ]]
        then
            log_success "✔️ Warning/Error log for ${log_description} '${cidr_to_check}' found."
            INVALID_CIDR_LOG_COUNT=$((INVALID_CIDR_LOG_COUNT + 1))
        else
            log_warn "⚠️ Warning/Error log for ${log_description} '${cidr_to_check}' NOT found."
        fi
    }

    check_invalid_cidr_log "192.168.300.1/24" "Invalid CIDR (Ingress)"
    check_invalid_cidr_log "10.0.0.0/33" "Invalid CIDR (Ingress))"
    check_invalid_cidr_log "not-a-cidr" "Invalid STRING (Ingress)"
    check_invalid_cidr_log "256.0.0.1/32" "Invalid CIDR (Egress)"

    if [[ "$INVALID_CIDR_LOG_COUNT" -lt "$EXPECTED_INVALID_LOGS" ]]
    then
        log_warn "⚠️ Number of invalid CIDR logs (${INVALID_CIDR_LOG_COUNT}) less than expected (${EXPECTED_INVALID_LOGS})."
        if [[ "$DEBUG_E2E_LOGS" != "true" ]]; then 
            log_info "--- Relevant Controller Logs (Warnings/Errors) ---"
            echo "${LOG_OUTPUT_FULL}" | grep -i -E "Warning|Error|Failed to parse|Skipping|invalid CIDR" | tail -n 30 
            log_info "----------------------------------------------------"
        fi
    else
        log_success "✔️ All expected ${EXPECTED_INVALID_LOGS} logs for invalid CIDRs/strings were found."
    fi
else
    log_warn "⚠️ Unable to check controller logs."
fi

if [[ -n "$CONTROLLER_POD_NAME_LOGS" ]]
then
    log_info "🔎 Checking NftPodChainMetadataCache for ${TARGET_POD_NAME}..."
    EXPECTED_CACHE_KEY_INGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"
    EXPECTED_CACHE_KEY_EGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_egress"
    
    log_info "   Looking for Ingress Cache Key: ${EXPECTED_CACHE_KEY_INGRESS} (expecting PolicyIngressRuleCount:2, PolicyRuleCount:1)"
    ALL_INGRESS_CACHE_LOGS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_LOGS}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION} | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}")
    LATEST_VALID_INGRESS_LOG=$(echo "$ALL_INGRESS_CACHE_LOGS" | grep "Added/Updated" | \
        grep "PolicyName: ${MNP_NAMESPACE}/${MNP_NAME}" | \
        grep "PolicyIngressRuleCount: 2" | grep "PolicyEgressRuleCount: 2" | \
        grep "IsIsolationChain:false" | grep "PolicyRuleCount:1" | tail -n 1 || echo "")
        
    if [[ -z "$LATEST_VALID_INGRESS_LOG" ]]
    then 
        log_error "❌ Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} missing or incorrect."
        if [[ "$DEBUG_E2E_LOGS" == "true" ]]
        then
             echo "Logs for Ingress key (${EXPECTED_CACHE_KEY_INGRESS}):"
             echo "${ALL_INGRESS_CACHE_LOGS:- (No log)}"
        fi
    else
        log_success "✔️ Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} found and correct."
    fi

    log_info "   Looking for Egress Cache Key: ${EXPECTED_CACHE_KEY_EGRESS} (expecting PolicyEgressRuleCount:2, PolicyRuleCount:1)"
    ALL_EGRESS_CACHE_LOGS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_LOGS}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION} | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_EGRESS}")
    LATEST_VALID_EGRESS_LOG=$(echo "$ALL_EGRESS_CACHE_LOGS" | grep "Added/Updated" | \
        grep "PolicyName: ${MNP_NAMESPACE}/${MNP_NAME}" | \
        grep "PolicyIngressRuleCount: 2" | grep "PolicyEgressRuleCount: 2" | \
        grep "IsIsolationChain:false" | grep "PolicyRuleCount:1" | tail -n 1 || echo "")
        
    if [[ -z "$LATEST_VALID_EGRESS_LOG" ]]
    then 
        log_error "❌ Cache Egress entry for ${EXPECTED_CACHE_KEY_EGRESS} missing or incorrect."
        if [[ "$DEBUG_E2E_LOGS" == "true" ]]
        then
            echo "Logs for Egress Key (${EXPECTED_CACHE_KEY_EGRESS}):"
            echo "${ALL_EGRESS_CACHE_LOGS:- (no log)}"
        fi
    else
        log_success "✔️ Cache Egress entry for ${EXPECTED_CACHE_KEY_EGRESS} found and correct."
    fi
else
    log_warn "⚠️ Unable to verify NftPodChainMetadataCache."
fi

# Fail the test if the invalid CIDR logs were not found OR if the cache is incorrect
FINAL_TEST_SUCCESS=true
if [[ "$INVALID_CIDR_LOG_COUNT" -lt "$EXPECTED_INVALID_LOGS" ]]
then
    log_error "❌ Test failed due to missing invalid CIDR logs."
    FINAL_TEST_SUCCESS=false
fi
if [[ -n "$CONTROLLER_POD_NAME_LOGS" ]]
then
    if [[ -z "$LATEST_VALID_INGRESS_LOG" ]] || [[ -z "$LATEST_VALID_EGRESS_LOG" ]]
    then
        log_error "❌ Test failed due to incorrect NftPodChainMetadataCache."
        FINAL_TEST_SUCCESS=false
    fi
fi

if [[ "$FINAL_TEST_SUCCESS" == "true" ]];
then
    log_info "✅ Test finished: ${TEST_NAME}"
else
    exit 1
fi
