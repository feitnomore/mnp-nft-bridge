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

NAD_BRIDGE_FILE="${SCENARIO_DIR}/00_nad_bridge.yaml"
NAD_MACVLAN_FILE="${SCENARIO_DIR}/01_nad_e2e_test_macvlan.yaml"
POD_FILE="${SCENARIO_DIR}/02_pod_multi_interface.yaml"
MNP_FILE="${SCENARIO_DIR}/03_mnp_for_bridge_interface.yaml"

TARGET_POD_NAME="pod-multi-interface"
POD_NAMESPACE="default"
MNP_NAME="policy-for-bridge-interface"
MNP_NAMESPACE="default"

# NADs are created in the 'default' namespace
NAD_BRIDGE_NAME_IN_MANIFEST="e2e-test-bridge"
NAD_MACVLAN_NAME_IN_MANIFEST="e2e-test-macvlan"
NAD_NAMESPACE_IN_MANIFEST="default"

# MultiNetworkPolicy and Pod reference the NAD bridge
POLICY_FOR_NAD_NAME="${NAD_BRIDGE_NAME_IN_MANIFEST}"
POLICY_FOR_NAD_NAMESPACE_REF="${NAD_NAMESPACE_IN_MANIFEST}"


NFT_CONTROLLER_NAMESPACE="kube-system"
NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"

TARGET_POD_BRIDGE_MAC_GLOBAL="" # MAC of the bridge interface (net1)
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
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_BRIDGE_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_MACVLAN_FILE}"

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
            log_error "❌ CLEANUP ERROR: Chain ${EXPECTED_INGRESS_CHAIN_GLOBAL} still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -q "set mnp-"; then
            log_error "❌ CLEANUP ERROR: 'mnp-' sets still exist!"
            ERROR_FOUND_CLEANUP=1
        fi
        if [[ -n "$TARGET_POD_BRIDGE_MAC_GLOBAL" ]] && echo "$FINAL_RULESET" | grep -q "ether daddr ${TARGET_POD_BRIDGE_MAC_GLOBAL} jump"; then
            log_error "❌ CLEANUP ERROR: JUMP Ingress rule for MAC ${TARGET_POD_BRIDGE_MAC_GLOBAL} still exists!"
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

# Modified to get the MAC of a specific interface (based on the NAD name)
get_specific_interface_mac() {
    local pod_name="$1"
    local pod_ns="$2"
    local nad_name_ref="$3" # Ex: "default/e2e-test-bridge" or "e2e-test-bridge" if on the same NS as the pod
    local attempts=0
    local max_attempts=12
    local mac_address=""

    log_info "🔎 Trying to get MAC address for pod ${pod_ns}/${pod_name} on network ${nad_name_ref}..."
    while [[ -z "$mac_address" && "$attempts" -lt "$max_attempts" ]]
    do
        mac_address=$(${KUBECTL} get pod "$pod_name" -n "$pod_ns" -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/network-status}' 2>/dev/null | \
                      jq -r --arg NAD_TARGET_NAME "${nad_name_ref}" '.[] | select(.name == $NAD_TARGET_NAME) | .mac' 2>/dev/null || echo "")
        
        # Fallback if NAD is referenced without namespace (assuming pod namespace)
        if [[ -z "$mac_address" && "$nad_name_ref" != *"/"* ]]
        then
             mac_address=$(${KUBECTL} get pod "$pod_name" -n "$pod_ns" -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/network-status}' 2>/dev/null | \
                      jq -r --arg NAD_TARGET_NAME_NO_NS "${nad_name_ref}" '.[] | select(.name == $NAD_TARGET_NAME_NO_NS) | .mac' 2>/dev/null || echo "")
        fi


        if [[ -n "$mac_address" ]]
        then
            log_success "✔️ MAC address for ${pod_ns}/${pod_name} on network ${nad_name_ref} is: ${mac_address}"
            echo "$mac_address"
            return 0
        fi
        attempts=$((attempts + 1))
        log_info "⏳ MAC not found for ${pod_ns}/${pod_name} on network ${nad_name_ref} (attempt ${attempts}/${max_attempts}). Waiting 5s..."
        sleep 5
    done
    log_error "❌ Failed to get MAC address for ${pod_ns}/${pod_name} on network ${nad_name_ref} after ${max_attempts} attempts."
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
    if ! ${EXEC_KIND} nft list chain bridge filter "${expected_chain_name}" > /dev/null 2>&1; then
        log_error "❌ ${state_label} Chain Ingress ${expected_chain_name} NOT found."; return 1
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
    if [[ "$IS_SINGLE_IP" == true ]]; then
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


TEST_NAME=$(cat "${SCENARIO_DIR}/test.def")

log_info "🚀 Starting E2E Test: ${TEST_NAME}"

# 1. Initial Setup
${KUBECTL} apply -f "${NAD_BRIDGE_FILE}"
${KUBECTL} apply -f "${NAD_MACVLAN_FILE}"
${KUBECTL} apply -f "${POD_FILE}"
${KUBECTL} apply -f "${MNP_FILE}" # MultiNetworkPolicy is for bridge interface

log_info "⏳ Waiting for pod ${TARGET_POD_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${POD_NAMESPACE}" --timeout=240s

# Get the MAC of the bridge interface (net1, associated with e2e-test-bridge)
# The k8s.v1.cni.cncf.io/networks annotation on the pod is "e2e-test-bridge, e2e-test-macvlan"
# Network status typically follows this order.
# The MNP points to "default/e2e-test-bridge".
TARGET_POD_BRIDGE_MAC_GLOBAL=$(get_specific_interface_mac "${TARGET_POD_NAME}" "${POD_NAMESPACE}" "${NAD_NAMESPACE_IN_MANIFEST}/${NAD_BRIDGE_NAME_IN_MANIFEST}")
if [[ -z "$TARGET_POD_BRIDGE_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of the BRIDGE interface of pod ${TARGET_POD_NAME} not found."
    exit 1
fi

# Optional: Get the MAC of the macvlan interface to ensure it is different and not being used
TARGET_POD_MACVLAN_MAC=$(get_specific_interface_mac "${TARGET_POD_NAME}" "${POD_NAMESPACE}" "${NAD_NAMESPACE_IN_MANIFEST}/${NAD_MACVLAN_NAME_IN_MANIFEST}")
if [[ -n "$TARGET_POD_MACVLAN_MAC" ]]
then
    log_info "ℹ️ MAC of pod's MACVLAN interface ${TARGET_POD_NAME} is: ${TARGET_POD_MACVLAN_MAC}"
    if [[ "$TARGET_POD_BRIDGE_MAC_GLOBAL" == "$TARGET_POD_MACVLAN_MAC" ]]
    then
        log_warn "⚠️ The bridge interface MAC and MACVLAN are the same. This can complicate verification.."
    fi
else
    log_warn "⚠️ Unable to get MACVLAN interface MAC of pod ${TARGET_POD_NAME}."
fi


log_info "⏳ Waiting for mnp-nft-bridge controller to apply initial state (30 seconds)..."
sleep 30

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Could not get Kind's control-plane ID."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${POD_NAMESPACE}" "${TARGET_POD_NAME}")
EXPECTED_INGRESS_CHAIN_GLOBAL="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"
INGRESS_CIDR_FROM_MNP="192.168.100.120/32"
INGRESS_PORT_FROM_MNP="80"

log_info "🔎 === Checking Initial State (Rules Applied Only to Bridge Interface) ==="
verify_ingress_rules_state "[Initial]" "${TARGET_POD_BRIDGE_MAC_GLOBAL}" "${EXPECTED_INGRESS_CHAIN_GLOBAL}" \
    "${INGRESS_CIDR_FROM_MNP}" "${INGRESS_PORT_FROM_MNP}" || exit 1
log_success "✔️ [Initial] Nftables status for bridge interface verified successfully."

log_info "🔎 [Initial] Checking for ABSENCE of JUMP rules for interface MACVLAN (MAC: ${TARGET_POD_MACVLAN_MAC:-N/A})..."
if [[ -n "$TARGET_POD_MACVLAN_MAC" && "$TARGET_POD_MACVLAN_MAC" != "$TARGET_POD_BRIDGE_MAC_GLOBAL" ]]
then
    JUMP_RULE_FOR_MACVLAN=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
        grep -F "ether daddr ${TARGET_POD_MACVLAN_MAC} jump KUBE_MULTI_INGRESS_" || echo "NOT_FOUND")
    if [[ "$JUMP_RULE_FOR_MACVLAN" != "NOT_FOUND" ]]
    then
        log_error "❌ [Initial] JUMP Ingress rule for MAC of interface MACVLAN (${TARGET_POD_MACVLAN_MAC}) WAS found, but should not be found.."
        exit 1
    fi
    log_success "✔️ [Initial] No JUMP Ingress rule for MACVLAN interface MAC found, as expected."
else
    log_warn "⚠️ [Initial] MAC of the MACVLAN interface not available or equal to that of the bridge, skipping the check for the absence of a jump to MACVLAN."
fi

# Check NftPodChainMetadataCache
CONTROLLER_POD_NAME_INITIAL=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME_INITIAL" ]]
then
    log_info "🔎 [Initial] Checking NftPodChainMetadataCache for ${TARGET_POD_NAME} (bridge interface)..."
    EXPECTED_CACHE_KEY_INGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"
    
    CACHE_LOG_INGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_INITIAL}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" | \
        grep "PolicyIngressRuleCount: 1" | grep "PolicyName: ${MNP_NAMESPACE}/${MNP_NAME}" | grep "IsIsolationChain:false" | tail -n 1 || echo "")
        
    if [[ -z "$CACHE_LOG_INGRESS" ]]
    then
        log_error "❌ [Initial] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} missing or incorrect."
        ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_INITIAL}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" || echo "(no log for this key)"
        exit 1
    fi
    log_success "✔️ [Initial] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} found and correct."
else
    log_warn "⚠️ [Initial] Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
