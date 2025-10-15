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
POD_FILE="${SCENARIO_DIR}/01_target_pod_for_reconcile.yaml"
MNP_FILE="${SCENARIO_DIR}/02_mnp_for_reconcile_test.yaml"

TARGET_POD_NAME="target-pod-for-reconcile"
POD_NAMESPACE="default"
MNP_NAME="policy-for-reconcile-test"
MNP_NAMESPACE="default"

NAD_NAME_IN_MANIFEST="e2e-test-bridge"
NAD_NAMESPACE_IN_MANIFEST="default"

NFT_CONTROLLER_DAEMONSET_NAME="mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"
NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"

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

    log_info "  Ensuring the controller pod is ready for the next test..."
    local controller_pod_name_cleanup
    controller_pod_name_cleanup=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [[ -n "$controller_pod_name_cleanup" ]]
    then
        # Check if the pod exists and is ready
        if ${KUBECTL} get pod "$controller_pod_name_cleanup" -n "${NFT_CONTROLLER_NAMESPACE}" > /dev/null 2>&1; then
            if ! ${KUBECTL} get pod "$controller_pod_name_cleanup" -n "${NFT_CONTROLLER_NAMESPACE}" -o jsonpath='{.status.containerStatuses[?(@.name=="mnp-nft-bridge")].ready}' | grep -q true; then
                log_warn "  Controller pod ${controller_pod_name_cleanup} is not ready. Waiting..."
                ${KUBECTL} wait --for=condition=Ready pod/"${controller_pod_name_cleanup}" -n "${NFT_CONTROLLER_NAMESPACE}" --timeout=180s || log_warn "⚠️ Controller pod not ready after scaling in cleanup."
            else
                log_info "  Controller pod ${controller_pod_name_cleanup} is now ready."
            fi
        else
             log_warn "  Controller pod ${controller_pod_name_cleanup} not found. DaemonSet must recreate it."
             # Wait for DS to have at least one replica ready
            ${KUBECTL} wait daemonset/"${NFT_CONTROLLER_DAEMONSET_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --for=jsonpath='{.status.numberReady}'=1 --timeout=120s || log_warn "⚠️ Controller DaemonSet not ready on cleanup."
        fi
    else
        log_warn "⚠️ Could not find controller pod during cleanup to check Ready status. Checking DaemonSet..."
        ${KUBECTL} wait daemonset/"${NFT_CONTROLLER_DAEMONSET_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --for=jsonpath='{.status.numberReady}'=1 --timeout=120s || log_warn "⚠️ Controller DaemonSet not ready on cleanup."
    fi

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
        if echo "$FINAL_RULESET" | grep -qE "KUBE_MULTI_(INGRESS|EGRESS)_[0-9a-fA-F]{12}"; then
            log_error "❌ CLEANUP ERROR: Pod-specific KUBE_MULTI chain still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -q "set mnp-"; then
            log_error "❌ CLEANUP ERROR: 'mnp-' sets still exist!"
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

verify_rules_state() {
    local state_label="$1"
    local pod_mac_to_check="$2"
    local expected_chain_suffix="$3"
    local expected_ingress_cidr_param="$4"
    local expected_ingress_port="$5"
    local expected_egress_cidr_param="$6"
    local expected_egress_port="$7"

    local expected_ingress_chain_name="KUBE_MULTI_INGRESS_${expected_chain_suffix}"
    local expected_egress_chain_name="KUBE_MULTI_EGRESS_${expected_chain_suffix}"

    log_info "🔎 ${state_label} Checking JUMP Ingress for MAC ${pod_mac_to_check} for ${expected_ingress_chain_name}..."
    JUMP_RULE_INGRESS=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
        grep -F "ether daddr ${pod_mac_to_check} jump ${expected_ingress_chain_name}" || echo "NOT_FOUND")
    if [[ "$JUMP_RULE_INGRESS" == "NOT_FOUND" ]]
    then
        log_error "❌ ${state_label} JUMP Ingress rule NOT found."
        return 1
    fi
    log_success "✔️ ${state_label} JUMP Ingress rule found."

    log_info "🔎 ${state_label} Checking JUMP Egress for MAC ${pod_mac_to_check} for ${expected_egress_chain_name}..."
    JUMP_RULE_EGRESS=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
        grep -F "ether saddr ${pod_mac_to_check} jump ${expected_egress_chain_name}" || echo "NOT_FOUND")
    if [[ "$JUMP_RULE_EGRESS" == "NOT_FOUND" ]]
    then
        log_error "❌ ${state_label} JUMP Egress rule NOT found."
        return 1
    fi
    log_success "✔️ ${state_label} JUMP Egress rule found."

    # Verify Ingress chain contents
    log_info "🔎 ${state_label} Checking rules inside Ingress chain ${expected_ingress_chain_name}..."
    INGRESS_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${expected_ingress_chain_name}")

    INGRESS_IP_FOR_SET_CHECK="${expected_ingress_cidr_param%%/*}"
    IS_SINGLE_IP_INGRESS=false
    if [[ "$expected_ingress_cidr_param" == *"/"* ]]
    then
        MASK_PART_INGRESS="${expected_ingress_cidr_param#*/}"
        if [[ "$MASK_PART_INGRESS" == "32" ]]
        then
            IS_SINGLE_IP_INGRESS=true
        fi
    else
        IS_SINGLE_IP_INGRESS=true
        INGRESS_IP_FOR_SET_CHECK="$expected_ingress_cidr_param"
    fi

    INGRESS_RULE_LINE=""
    if [[ "$IS_SINGLE_IP_INGRESS" == true ]]
    then
        INGRESS_RULE_LINE=$(echo "$INGRESS_CHAIN_RULES" | grep "ip saddr @mnp-src-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    else
        INGRESS_RULE_LINE=$(echo "$INGRESS_CHAIN_RULES" | grep -F "ip saddr ${expected_ingress_cidr_param}" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    fi

    if [[ -z "$INGRESS_RULE_LINE" ]]
    then
        log_error "❌ ${state_label} Ingress rule (CIDR/IP ${expected_ingress_cidr_param} -> TCP Port Set) not found."
        echo "$INGRESS_CHAIN_RULES"
        return 1
    fi

    TCP_PORT_SET_NAME_INGRESS=$(echo "$INGRESS_RULE_LINE" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
    if [[ -z "$TCP_PORT_SET_NAME_INGRESS" ]]
    then
        log_error "❌ ${state_label} Failed to extract name from TCP Ingress port set."
        return 1
    fi
    ${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME_INGRESS}" | grep -qE "(^|[[:space:],{])${expected_ingress_port}([[:space:],}]|$)" || \
        { log_error "❌ ${state_label} Set Ingress ${TCP_PORT_SET_NAME_INGRESS} does not contain port ${expected_ingress_port}."; return 1; }

    if [[ "$IS_SINGLE_IP_INGRESS" == true ]]
    then
        SRC_IP_SET_NAME=$(echo "$INGRESS_RULE_LINE" | grep -o 'mnp-src-ip-[a-f0-9]\{16\}' | head -n1)
        if [[ -z "$SRC_IP_SET_NAME" ]]
        then
            log_error "❌ ${state_label} Failed to extract Ingress source IP set name."
            return 1
        fi
        ${EXEC_KIND} nft list set bridge filter "${SRC_IP_SET_NAME}" | grep -qF "${INGRESS_IP_FOR_SET_CHECK}" || \
            { log_error "❌ ${state_label} Set Ingress ${SRC_IP_SET_NAME} does not contain ${INGRESS_IP_FOR_SET_CHECK}."; return 1; }
    fi
    log_success "✔️ ${state_label} Ingress rules verified."

    # Verify Egress chain contents
    log_info "🔎 ${state_label} Checking rules inside Egress chain ${expected_egress_chain_name}..."
    EGRESS_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${expected_egress_chain_name}")

    EGRESS_IP_FOR_SET_CHECK="${expected_egress_cidr_param%%/*}"
    IS_SINGLE_IP_EGRESS=false
    if [[ "$expected_egress_cidr_param" == *"/"* ]]
    then
        MASK_PART_EGRESS="${expected_egress_cidr_param#*/}"
        if [[ "$MASK_PART_EGRESS" == "32" ]]
        then
            IS_SINGLE_IP_EGRESS=true
        fi
    else
        IS_SINGLE_IP_EGRESS=true
        EGRESS_IP_FOR_SET_CHECK="$expected_egress_cidr_param"
    fi

    EGRESS_RULE_LINE=""
    if [[ "$IS_SINGLE_IP_EGRESS" == true ]]
    then
        EGRESS_RULE_LINE=$(echo "$EGRESS_CHAIN_RULES" | grep "ip daddr @mnp-dst-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    else
        EGRESS_RULE_LINE=$(echo "$EGRESS_CHAIN_RULES" | grep -F "ip daddr ${expected_egress_cidr_param}" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    fi

    if [[ -z "$EGRESS_RULE_LINE" ]]
    then
        log_error "❌ ${state_label} Egress rule (CIDR/IP ${expected_egress_cidr_param} -> TCP Port Set) not found."
        echo "$EGRESS_CHAIN_RULES"
        return 1
    fi

    TCP_PORT_SET_NAME_EGRESS=$(echo "$EGRESS_RULE_LINE" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
    if [[ -z "$TCP_PORT_SET_NAME_EGRESS" ]]
    then
        log_error "❌ ${state_label} Failed to extract name from TCP Egress port set."
        return 1
    fi
    ${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME_EGRESS}" | grep -qE "(^|[[:space:],{])${expected_egress_port}([[:space:],}]|$)" || \
        { log_error "❌ ${state_label} Set Egress ${TCP_PORT_SET_NAME_EGRESS} does not contain port ${expected_egress_port}."; return 1; }

    if [[ "$IS_SINGLE_IP_EGRESS" == true ]]
    then
        DST_IP_SET_NAME=$(echo "$EGRESS_RULE_LINE" | grep -o 'mnp-dst-ip-[a-f0-9]\{16\}' | head -n1)
        if [[ -z "$DST_IP_SET_NAME" ]]
        then
            log_error "❌ ${state_label} Failed to extract Egress target IP set name."
            return 1
        fi
        ${EXEC_KIND} nft list set bridge filter "${DST_IP_SET_NAME}" | grep -qF "${EGRESS_IP_FOR_SET_CHECK}" || \
            { log_error "❌ ${state_label} Set Egress ${DST_IP_SET_NAME} does not contain ${EGRESS_IP_FOR_SET_CHECK}."; return 1; }
    fi
    log_success "✔️ ${state_label} Egress Rules Verified."

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

log_info "⏳ Waiting for mnp-nft-bridge controller to apply initial state (30 seconds)..."
sleep 30

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Could not get Kind's control-plane ID."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${POD_NAMESPACE}" "${TARGET_POD_NAME}")
INGRESS_CIDR_FROM_MNP="192.168.100.100/32"
INGRESS_PORT_FROM_MNP="80"
EGRESS_CIDR_FROM_MNP="10.100.0.0/16"
EGRESS_PORT_FROM_MNP="443"

log_info "🔎 === Checking Initial State (Rules Applied) ==="
verify_rules_state "[Initial]" "${TARGET_POD_MAC_GLOBAL}" "${EXPECTED_CHAIN_SUFFIX_GLOBAL}" \
    "${INGRESS_CIDR_FROM_MNP}" "${INGRESS_PORT_FROM_MNP}" \
    "${EGRESS_CIDR_FROM_MNP}" "${EGRESS_PORT_FROM_MNP}" || exit 1
log_success "✔️ [Initial] Initial nftables state verified successfully."

# 2. Action: Simulate controller restart by deleting its pod
log_info "🔩 Deleting pod from mnp-nft-bridge controller to simulate restart..."
CONTROLLER_POD_TO_DELETE=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [[ -z "$CONTROLLER_POD_TO_DELETE" ]]
then
    log_error "❌ Could not find mnp-nft-bridge controller pod to delete."
    exit 1
fi
if ! ${KUBECTL} delete pod "${CONTROLLER_POD_TO_DELETE}" -n "${NFT_CONTROLLER_NAMESPACE}" --grace-period=0 --force; then
    log_error "❌ Failed to delete pod from controller ${CONTROLLER_POD_TO_DELETE}."
    exit 1
fi
log_info "✔️ Controller pod ${CONTROLLER_POD_TO_DELETE} deleted."

log_info "⏳ Waiting for DaemonSet to recreate the controller pod and make it ready (up to 2 minutes)..."
# Wait for the DS to have the desired number of pods ready.
# For a 1-node Kind, we expect 1 replica of the DaemonSet.
${KUBECTL} wait daemonset/"${NFT_CONTROLLER_DAEMONSET_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --for=jsonpath='{.status.numberReady}'=1 --timeout=120s
NEW_CONTROLLER_POD_NAME=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [[ -z "$NEW_CONTROLLER_POD_NAME" ]]
then
    log_error "❌ New controller pod not found after deletion."
    exit 1
fi
${KUBECTL} wait --for=condition=Ready pod/"${NEW_CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --timeout=180s
log_success "✔️ Controller pod mnp-nft-bridge (${NEW_CONTROLLER_POD_NAME}) has been recreated and is ready."

log_info "⏳ Waiting for the restarted controller to reconcile state (60 seconds)..."
sleep 60

# 3. Post-Restart Controller Checks
log_info "🔎 === Checking Controller Post-Restart Status ==="
verify_rules_state "[Post-Restart]" "${TARGET_POD_MAC_GLOBAL}" "${EXPECTED_CHAIN_SUFFIX_GLOBAL}" \
    "${INGRESS_CIDR_FROM_MNP}" "${INGRESS_PORT_FROM_MNP}" \
    "${EGRESS_CIDR_FROM_MNP}" "${EGRESS_PORT_FROM_MNP}" || exit 1
log_success "✔️ [Post-Restart] Nftables status after controller restart verified successfully."

# Check NftPodChainMetadataCache (must be repopulated)
if [[ -n "$NEW_CONTROLLER_POD_NAME" ]]
then
    log_info "🔎 [Post-Restart] Checking NftPodChainMetadataCache in logs for pod ${NEW_CONTROLLER_POD_NAME}..."
    EXPECTED_CACHE_KEY_INGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"
    EXPECTED_CACHE_KEY_EGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_egress"

    sleep 10 # Give logs time to be written

    CACHE_LOG_INGRESS=$(${KUBECTL} logs "pod/${NEW_CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=3m | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" | \
        grep "PolicyIngressRuleCount: 1" | grep "PolicyEgressRuleCount: 1" | grep "IsIsolationChain:false" | tail -n 1 || echo "")

    if [[ -z "$CACHE_LOG_INGRESS" ]]
    then
        log_error "❌ [Post-Restart] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} not found or incorrect after restart."
        ${KUBECTL} logs "pod/${NEW_CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=3m | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" || echo "(no log found for the key)"
        exit 1
    fi
    log_success "✔️ [Post-Restart] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} found and correct."

    CACHE_LOG_EGRESS=$(${KUBECTL} logs "pod/${NEW_CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=3m | \
        grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_EGRESS}" | \
        grep "PolicyIngressRuleCount: 1" | grep "PolicyEgressRuleCount: 1" | grep "IsIsolationChain:false" | tail -n 1 || echo "")

    if [[ -z "$CACHE_LOG_EGRESS" ]]
    then
        log_error "❌ [Post-Restart] Cache Egress entry for ${EXPECTED_CACHE_KEY_EGRESS} missing or incorrect after restart."
        ${KUBECTL} logs "pod/${NEW_CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=3m | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_EGRESS}" || echo "(no log found for the key)"
        exit 1
    fi
    log_success "✔️ [Post-Restart] Cache Egress entry for ${EXPECTED_CACHE_KEY_EGRESS} found and correct."
else
    log_warn "⚠️ [Post-Restart] Unable to verify NftPodChainMetadataCache (new controller pod not found)."
fi

log_info "✅ Test finished: ${TEST_NAME}"
