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
POD_FILE="${SCENARIO_DIR}/01_target_pod_policytypes_test.yaml"
MNP_FILE="${SCENARIO_DIR}/02_mnp_explicit_ingress_only.yaml"

TARGET_POD_NAME="target-pod-policytypes-test"
POD_NAMESPACE="default"
MNP_NAME="policy-ingress-only-defined"
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
        log_info "  Waiting a little longer for the reconciler (10s)..."
        sleep 10
        FINAL_RULESET=$(${EXEC_KIND} nft list ruleset bridge)

        ERROR_FOUND_CLEANUP=0
        if [[ -n "$EXPECTED_INGRESS_CHAIN_GLOBAL" ]] && echo "$FINAL_RULESET" | grep -qF "chain ${EXPECTED_INGRESS_CHAIN_GLOBAL}"; then
            log_error "❌ CLEANUP ERROR: Chain Ingress ${EXPECTED_INGRESS_CHAIN_GLOBAL} still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if [[ -n "$EXPECTED_CHAIN_SUFFIX_GLOBAL" ]] && echo "$FINAL_RULESET" | grep -qF "chain KUBE_MULTI_EGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"; then
            log_error "❌ CLEANUP ERROR: Chain Egress KUBE_MULTI_EGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL} still exists!"
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
         if [[ -n "$TARGET_POD_MAC_GLOBAL" ]] && echo "$FINAL_RULESET" | grep -q "ether saddr ${TARGET_POD_MAC_GLOBAL} jump"; then
            log_error "❌ CLEANUP ERROR: JUMP Egress rule for MAC ${TARGET_POD_MAC_GLOBAL} still exists!"
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

verify_ingress_rules_state() {
    local state_label="$1"
    local pod_mac="$2"
    local expected_chain_name="$3"
    local expected_cidr="$4"
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
    if ! ${EXEC_KIND} nft list chain bridge filter "${expected_chain_name}" > /dev/null 2>&1
    then
        log_error "❌ ${state_label} Chain Ingress ${expected_chain_name} NOT found."
        return 1
    fi
    log_success "✔️ ${state_label} Chain Ingress ${expected_chain_name} found."

    log_info "🔎 ${state_label} Checking rules within chain ${expected_chain_name}..."
    INGRESS_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${expected_chain_name}")

    IP_FOR_SET_CHECK="${expected_cidr%%/*}"
    IS_SINGLE_IP=false
    if [[ "$expected_cidr" == *"/"* ]]
    then
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
        log_error "❌ ${state_label} Ingress rule (CIDR/IP ${expected_cidr} -> TCP Port Set) not found."
        echo "$INGRESS_CHAIN_RULES"
        return 1
    fi

    TCP_PORT_SET_NAME=$(echo "$RULE_LINE" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
    if [[ -z "$TCP_PORT_SET_NAME" ]]
    then
        log_error "❌ ${state_label} Failed to extract name from TCP Ingress port set."
        return 1
    fi

    ${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME}" | grep -qE "(^|[[:space:],{])${expected_port}([[:space:],}]|$)" || \
        { log_error "❌ ${state_label} Set Ingress ${TCP_PORT_SET_NAME} does not contain port ${expected_port}."; return 1; }

    if [[ "$IS_SINGLE_IP" == true ]]
    then
        SRC_IP_SET_NAME=$(echo "$RULE_LINE" | grep -o 'mnp-src-ip-[a-f0-9]\{16\}' | head -n1)
        if [[ -z "$SRC_IP_SET_NAME" ]]
        then
            log_error "❌ ${state_label} Failed to extract Ingress source IP set name."
            return 1
        fi
        ${EXEC_KIND} nft list set bridge filter "${SRC_IP_SET_NAME}" | grep -qF "${IP_FOR_SET_CHECK}" || \
            { log_error "❌ ${state_label} Set Ingress ${SRC_IP_SET_NAME} does not contain ${IP_FOR_SET_CHECK}."; return 1; }
    fi
    log_success "✔️ ${state_label} Ingress rules and sets checked."
    return 0
}

verify_NO_egress_rules_for_pod() {
    local pod_mac="$1"
    local expected_chain_suffix="$2"
    local pod_label_for_log="$3"
    local potential_egress_chain_name="KUBE_MULTI_EGRESS_${expected_chain_suffix}"

    log_info "🔎 Checking for ABSENCE of JUMP Egress for MAC ${pod_mac} (${pod_label_for_log}) for chain ${potential_egress_chain_name}..."
    JUMP_RULE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
        grep -F "ether saddr ${pod_mac} jump ${potential_egress_chain_name}" || echo "NOT_FOUND")
    if [[ "$JUMP_RULE_OUTPUT" != "NOT_FOUND" ]]
    then
        log_error "❌ JUMP Egress rule for MAC ${pod_mac} (${pod_label_for_log}) for ${potential_egress_chain_name} WAS found, but it shouldn't have been."
        echo "Rule found: $JUMP_RULE_OUTPUT"
        return 1
    fi
    log_success "✔️ No JUMP Egress rule for MAC ${pod_mac} (${pod_label_for_log}) for ${potential_egress_chain_name} found, as expected."

    log_info "🔎 Checking for ABSENCE of Egress chain ${potential_egress_chain_name} (${pod_label_for_log})..."
    if ${EXEC_KIND} nft list chain bridge filter "${potential_egress_chain_name}" > /dev/null 2>&1; then
        log_error "❌ Egress chain ${potential_egress_chain_name} (${pod_label_for_log}) WAS found, but it shouldn't have been."
        return 1
    fi
    log_success "✔️ Egress chain ${potential_egress_chain_name} (${pod_label_for_log}) not found, as expected."
    return 0
}


TEST_NAME=$(cat "${SCENARIO_DIR}/test.def")

log_info "🚀 Starting E2E Test: ${TEST_NAME}"

# 1. Initial Setup
${KUBECTL} apply -f "${NAD_FILE}"
${KUBECTL} apply -f "${POD_FILE}"
${KUBECTL} apply -f "${MNP_FILE}"

log_info "⏳ Waiting for pod ${TARGET_POD_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${POD_NAMESPACE}" --timeout=240s
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
INGRESS_CIDR_FROM_MNP="192.168.100.130/32"
INGRESS_PORT_FROM_MNP="80"

log_info "🔎 === Checking Applied Rules (Only Ingress Should Be Effective) ==="
verify_ingress_rules_state "[Ingress-Check]" "${TARGET_POD_MAC_GLOBAL}" "${EXPECTED_INGRESS_CHAIN_GLOBAL}" \
    "${INGRESS_CIDR_FROM_MNP}" "${INGRESS_PORT_FROM_MNP}" || exit 1
log_success "✔️ [Ingress-Check] Ingress rules applied correctly."

verify_NO_egress_rules_for_pod "${TARGET_POD_MAC_GLOBAL}" "${EXPECTED_CHAIN_SUFFIX_GLOBAL}" "${TARGET_POD_NAME}" || exit 1
log_success "✔️ [Egress-Check] No Egress rules applied, as expected due to policyTypes."

CONTROLLER_POD_NAME_LOGS=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME_LOGS" ]]
then
    log_info "🔎 Checking NftPodChainMetadataCache for ${TARGET_POD_NAME}..."
    LOG_SINCE_DURATION="10m"; sleep 5

    EXPECTED_CACHE_KEY_INGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"
    # For MNP with policyTypes: ["Ingress"], spec.ingress: 1 rule, spec.egress: 1 rule
    # We expect in the Ingress chain metadata:
    # PolicyIngressRuleCount: 1 (since Ingress is a policyType and spec.ingress has 1 rule)
    # PolicyEgressRuleCount: 0 (since Egress is NOT a policyType)
    # PolicyRuleCount: 1 (since it is an Ingress chain and there is 1 effective Ingress rule)
    log_info "   Looking for Ingress cache key: ${EXPECTED_CACHE_KEY_INGRESS} with PolicyIngressRuleCount: 1, PolicyEgressRuleCount: 0, IsIsolationChain:false, PolicyRuleCount:1"

    ALL_INGRESS_CACHE_LOGS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_LOGS}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION} | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}")
    log_info "   Logs found for Ingress key (${EXPECTED_CACHE_KEY_INGRESS}):"
    echo "${ALL_INGRESS_CACHE_LOGS:- (No log)}"

    LATEST_VALID_INGRESS_LOG=$(echo "$ALL_INGRESS_CACHE_LOGS" | grep "Added/Updated" | \
        grep "PolicyName: ${MNP_NAMESPACE}/${MNP_NAME}" | \
        grep "PolicyIngressRuleCount: 1" | \
        grep "PolicyEgressRuleCount: 0" | \
        grep "IsIsolationChain:false" | \
        grep "PolicyRuleCount:1" | \
        tail -n 1 || echo "")

    if [[ -z "$LATEST_VALID_INGRESS_LOG" ]]
    then
        log_error "❌ Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} not found or has incorrect rule counts."
        exit 1;
    fi
    log_success "✔️ Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} found and correct."

    EXPECTED_CACHE_KEY_EGRESS_ABSENT="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_egress"
    log_info "   Checking for ABSENCE of Egress cache key: ${EXPECTED_CACHE_KEY_EGRESS_ABSENT}"
    ABSENT_EGRESS_CACHE_LOG=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_LOGS}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION} | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_EGRESS_ABSENT}" || echo "KEY_NOT_FOUND")
    if [[ "$ABSENT_EGRESS_CACHE_LOG" != "KEY_NOT_FOUND" ]]
    then
        log_error "❌ Cache Egress entry for ${EXPECTED_CACHE_KEY_EGRESS_ABSENT} WAS found, but it shouldn't have been."
        echo "Log found: $ABSENT_EGRESS_CACHE_LOG"
        exit 1
    fi
    log_success "✔️ No Cache Egress entry for ${EXPECTED_CACHE_KEY_EGRESS_ABSENT} found, as expected."
else
    log_warn "⚠️ Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"