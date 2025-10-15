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
NAMESPACE_FILE="${SCENARIO_DIR}/01_ns_for_edge04_test.yaml"
POD_FILE="${SCENARIO_DIR}/02_pod_in_ns_edge04.yaml"
MNP_FILE="${SCENARIO_DIR}/03_mnp_for_edge04.yaml"

TARGET_POD_NAME="pod-in-ns-edge04"
TARGET_NAMESPACE="ns-for-edge04-test"

MNP_NAME="policy-for-edge04"
MNP_NAMESPACE="${TARGET_NAMESPACE}"

POLICY_FOR_NAD_NAME="e2e-test-bridge"
POLICY_FOR_NAD_NAMESPACE_REF="default"

NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"

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
    # MNP, Pod, Namespace should already have been deleted by the test.
    # Use --ignore-not-found=true on all deletions in the cleanup to make it robust.
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${POD_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NAMESPACE_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"

    log_info "  Checking if ruleset is clean after cleanup..."
    KIND_CONTROL_PLANE_ID_CLEANUP=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
    if [[ -n "$KIND_CONTROL_PLANE_ID_CLEANUP" ]]; then
        log_info "  Waiting a bit more for reconciler (15s)..."
        sleep 15 # Give the reconciler extra time to process all deletions
        FINAL_RULESET=$(${EXEC_KIND} nft list ruleset bridge)

        ERROR_FOUND_CLEANUP=0
        if [[ -n "$EXPECTED_INGRESS_CHAIN_GLOBAL" ]] && echo "$FINAL_RULESET" | grep -qF "chain ${EXPECTED_INGRESS_CHAIN_GLOBAL}"; then
            log_error "❌ CLEANUP ERROR: Chain Ingress ${EXPECTED_INGRESS_CHAIN_GLOBAL} still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        # Add check for egress chain if MNP had egress
        if echo "$FINAL_RULESET" | grep -q "set mnp-"; then
            log_error "❌ CLEANUP ERROR: 'mnp-' sets still exist!"
            ERROR_FOUND_CLEANUP=1
        fi
        # We cannot check MACs here since the pod has been deleted.

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

    log_info "🔎 ${state_label} Checking if the chain ${expected_chain_name} exists..."
    if ! ${EXEC_KIND} nft list chain bridge filter "${expected_chain_name}" > /dev/null 2>&1; then
        log_error "❌ ${state_label} Chain Ingress ${expected_chain_name} NOT found."; return 1
    fi
    log_success "✔️ ${state_label} Chain Ingress ${expected_chain_name} found."

    log_info "🔎 ${state_label} Checking rules within chain ${expected_chain_name} for CIDR ${expected_cidr}..."
    INGRESS_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${expected_chain_name}")

    IP_FOR_SET_CHECK="${expected_cidr%%/*}"
    IS_SINGLE_IP=false
    if [[ "$expected_cidr" == *"/"* ]]; then
        MASK_PART="${expected_cidr#*/}"
        if [[ "$MASK_PART" == "32" ]]; then IS_SINGLE_IP=true; fi
    else
        IS_SINGLE_IP=true; IP_FOR_SET_CHECK="$expected_cidr"
    fi

    RULE_LINE=""
    if [[ "$IS_SINGLE_IP" == true ]]; then
        RULE_LINE=$(echo "$INGRESS_CHAIN_RULES" | grep "ip saddr @mnp-src-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | \
                    grep -E "mnp-src-ip-[0-9a-f]{16}.*mnp-tcp-port-[0-9a-f]{16}")
    else
        RULE_LINE=$(echo "$INGRESS_CHAIN_RULES" | grep -F "ip saddr ${expected_cidr}" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    fi

    if [[ -z "$RULE_LINE" ]]
    then
        log_error "❌ ${state_label} Ingress Rule (CIDR ${expected_cidr} -> TCP Port Set) not found."
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
            log_error "❌ ${state_label} Failed to extract name from Ingress source IP set."
            return 1
        fi
        ${EXEC_KIND} nft list set bridge filter "${SRC_IP_SET_NAME}" | grep -qF "${IP_FOR_SET_CHECK}" || \
            { log_error "❌ ${state_label} Set Ingress ${SRC_IP_SET_NAME} does not contain ${IP_FOR_SET_CHECK}."; return 1; }
    fi
    log_success "✔️ ${state_label} Ingress rule for CIDR ${expected_cidr} and port ${expected_port} checked."
    return 0
}

TEST_NAME=$(cat "${SCENARIO_DIR}/test.def")

log_info "🚀 Starting E2E Test: ${TEST_NAME}"

# 1. Initial Setup: Apply NAD, Namespace, Pod and MNP
${KUBECTL} apply -f "${NAD_FILE}"
${KUBECTL} apply -f "${NAMESPACE_FILE}"
${KUBECTL} apply -f "${POD_FILE}"
${KUBECTL} apply -f "${MNP_FILE}"

log_info "⏳ Waiting for pod ${TARGET_POD_NAME} in ${TARGET_NAMESPACE} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${TARGET_NAMESPACE}" --timeout=240s
TARGET_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${TARGET_NAMESPACE}")
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

EXPECTED_CHAIN_SUFFIX_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${TARGET_NAMESPACE}" "${TARGET_POD_NAME}")
EXPECTED_INGRESS_CHAIN_GLOBAL="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"

log_info "🔎 === Checking Initial State (NetworkAttachmentDefinition, Namespace, Pod and MultiNetworkPolicy exist and rules applied) ==="
verify_ingress_rules_state "[Initial]" "${TARGET_POD_MAC_GLOBAL}" "${EXPECTED_INGRESS_CHAIN_GLOBAL}" \
    "192.168.100.150/32" "80" || exit 1
log_success "✔️ [Initial] Initial state verified successfully."

# 2. Action: Delete the Pod and then the Namespace
log_info "🔩 Deleting Pod: ${POD_FILE}"
${KUBECTL} delete --ignore-not-found=true -f "${POD_FILE}"
log_info "⏳ Waiting for controller to process Pod deletion (20 seconds)..."
sleep 20

log_info "🔩 Deleting Namespace: ${NAMESPACE_FILE}"
${KUBECTL} delete --ignore-not-found=true -f "${NAMESPACE_FILE}"
log_info "⏳ Waiting for controller to process Namespace deletion (20 seconds)..."
sleep 20

#3. Post-Pod and Namespace Deletion Checks (MultiNetworkPolicy still exists, but should have no effect)
log_info "🔎 === Checking Status After Pod and Namespace Deletion (MultiNetworkPolicy Still Exists) ==="
log_info "🔎 [Post-Resources-Delete] Checking for ABSENCE of JUMP Ingress for MAC ${TARGET_POD_MAC_GLOBAL} to ${EXPECTED_INGRESS_CHAIN_GLOBAL}..."
JUMP_RULE_INGRESS_POST_DELETE=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_GLOBAL}" || echo "NOT_FOUND")
if [[ "$JUMP_RULE_INGRESS_POST_DELETE" != "NOT_FOUND" ]]
then
    log_error "❌ [Post-Resources-Delete] JUMP Ingress rule STILL EXISTS, but it shouldn't (Pod and NS deleted)."
    exit 1
fi
log_success "✔️ [Post-Resources-Delete] JUMP Ingress rule not found, as expected."

log_info "🔎 [Post-Resources-Delete] Checking if chain ${EXPECTED_INGRESS_CHAIN_GLOBAL} NO LONGER exists..."
if ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_GLOBAL}" > /dev/null 2>&1; then
    log_error "❌ [Post-Resources-Delete] Chain Ingress ${EXPECTED_INGRESS_CHAIN_GLOBAL} STILL EXISTS."
    exit 1
fi
log_success "✔️ [Post-Resources-Delete] Chain Ingress ${EXPECTED_INGRESS_CHAIN_GLOBAL} not found as expected."

log_info "🔎 [Post-Resources-Delete] Checking if 'mnp-' sets related to this chain have been removed..."
# Execute the command and capture the output. The '|| true' prevents the script from exiting if the command fails.
SETS_OUTPUT_POST_RESOURCES_DELETE=$(${EXEC_KIND} nft list sets bridge filter 2>&1 || true)

# Check output
if echo "$SETS_OUTPUT_POST_RESOURCES_DELETE" | grep -i -q "Error: No such file or directory"
then
    log_success "✔️ [Post-Resources-Delete] No sets found in table (received 'No such file or directory'), as expected."
elif echo "$SETS_OUTPUT_POST_RESOURCES_DELETE" | grep "mnp-" | grep -q "${EXPECTED_CHAIN_SUFFIX_GLOBAL}"
then
    log_error "❌ [Post-Resources-Delete] 'mnp-' sets related to suffix ${EXPECTED_CHAIN_SUFFIX_GLOBAL} STILL EXIST:"
    echo "$SETS_OUTPUT_POST_RESOURCES_DELETE" | grep "mnp-" | grep "${EXPECTED_CHAIN_SUFFIX_GLOBAL}"
    exit 1
else
    log_success "✔️ [Post-Resources-Delete] No set 'mnp-' related to suffix ${EXPECTED_CHAIN_SUFFIX_GLOBAL} found, as expected."
fi

log_info "✅ Test finished: ${TEST_NAME}"
