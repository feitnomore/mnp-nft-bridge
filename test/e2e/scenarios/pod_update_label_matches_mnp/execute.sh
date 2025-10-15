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
MNP_FILE="${SCENARIO_DIR}/01_mnp_selects_app_foo.yaml"
POD_INITIAL_FILE="${SCENARIO_DIR}/02_pod_initial_label_bar.yaml" 
POD_UPDATED_FILE="${SCENARIO_DIR}/03_pod_updated_label_foo.yaml" 

TARGET_POD_NAME="pod-for-label-update" 
POD_NAMESPACE="default" 
MNP_NAME="policy-selects-app-foo" 
MNP_NAMESPACE="default"

POLICY_FOR_NAD_NAME="e2e-test-bridge"
POLICY_FOR_NAD_NAMESPACE_REF="default"

NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"

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

    ${KUBECTL} delete pod "${TARGET_POD_NAME}" -n "${POD_NAMESPACE}" --ignore-not-found=true
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
        if [[ -n "$TARGET_POD_MAC_GLOBAL" ]]; then 
            if echo "$FINAL_RULESET" | grep -q "ether daddr ${TARGET_POD_MAC_GLOBAL} jump"; then
                 log_error "❌ CLEANUP ERROR: JUMP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} still exists!"
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

verify_ingress_rules_for_pod() {
    local pod_mac="$1"
    local expected_chain_name="$2"
    local expected_cidr_param="$3" 
    local expected_port="$4"
    local pod_label_for_log="$5"

    log_info "🔎 Checking JUMP Ingress for MAC ${pod_mac} for ${expected_chain_name} (${pod_label_for_log})..."
    JUMP_RULE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
        grep -F "ether daddr ${pod_mac} jump ${expected_chain_name}" || echo "")
    if [[ -z "$JUMP_RULE_OUTPUT" ]]
    then
        log_error "❌ JUMP Ingress rule for MAC ${pod_mac} for ${expected_chain_name} (${pod_label_for_log}) NOT found."
        ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
        return 1
    fi
    log_success "✔️ JUMP Ingress rule for ${expected_chain_name} (${pod_label_for_log}) found."

    log_info "🔎 Checking the PRESENCE of DROP Ingress for MAC ${pod_mac} (${pod_label_for_log}) in KUBE_MULTI_INGRESS..."
    DROP_RULE_BASE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
        grep -F "ether daddr ${pod_mac} drop" || echo "NOT_FOUND")
    if [[ "$DROP_RULE_BASE_OUTPUT" == "NOT_FOUND" ]]
    then
        log_error "❌ ${state_label} DROP Ingress rule for MAC ${pod_mac} (${pod_label_for_log}) was NOT found in KUBE_MULTI_INGRESS, but it should have been."
        ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
        return 1
    else
        log_success "✔️ ${state_label} DROP Ingress rule for MAC ${pod_mac} (${pod_label_for_log}) in KUBE_MULTI_INGRESS found, as expected."
    fi

    log_info "🔎 Checking rules inside chain ${expected_chain_name} (${pod_label_for_log})..."
    POD_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${expected_chain_name}")
    
    EXPECTED_IP_FOR_SET_CHECK="${expected_cidr_param%%/*}" 
    IS_SINGLE_IP_CIDR_CHECK=false
    if [[ "$expected_cidr_param" == *"/"* ]]
    then
        MASK_PART_CHECK="${expected_cidr_param#*/}"
        if [[ "$MASK_PART_CHECK" == "32" ]]
        then
            IS_SINGLE_IP_CIDR_CHECK=true
        fi
    else 
        IS_SINGLE_IP_CIDR_CHECK=true
        EXPECTED_IP_FOR_SET_CHECK="$expected_cidr_param"
    fi

    RULE_LINE=""
    if [[ "$IS_SINGLE_IP_CIDR_CHECK" == true ]]
    then
        RULE_LINE=$(echo "$POD_CHAIN_RULES" | grep "ip saddr @mnp-src-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    else
        RULE_LINE=$(echo "$POD_CHAIN_RULES" | grep "ip saddr ${expected_cidr_param}" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    fi

    if [[ -z "$RULE_LINE" ]]
    then
        log_error "❌ Ingress rule (Expected: ${expected_cidr_param} -> TCP/${expected_port}) not found in chain ${expected_chain_name} (${pod_label_for_log})."
        echo "Rules found in the chain:"
        echo "$POD_CHAIN_RULES"
        return 1
    fi
    
    TCP_PORT_SET_NAME=$(echo "$RULE_LINE" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
    if [[ -z "$TCP_PORT_SET_NAME" ]]
    then
        log_error "❌ Failed to extract TCP port set name from rule for ${pod_label_for_log}."
        return 1
    fi

    log_info "    Contents of TCP Port Set (${TCP_PORT_SET_NAME}) for ${pod_label_for_log}:"
    ${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME}" || echo "    Failed to list set ${TCP_PORT_SET_NAME}"
    ${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME}" | grep -qE "(^|[[:space:],{])${expected_port}([[:space:],}]|$)" || \
        { log_error "❌ Set ${TCP_PORT_SET_NAME} does not contain port ${expected_port} for ${pod_label_for_log}."; return 1; }

    if [[ "$IS_SINGLE_IP_CIDR_CHECK" == true ]]
    then
        SRC_IP_SET_NAME=$(echo "$RULE_LINE" | grep -o 'mnp-src-ip-[a-f0-9]\{16\}' | head -n1)
        if [[ -z "$SRC_IP_SET_NAME" ]]
        then
            log_error "❌ Failed to extract source IP set name from rule for ${pod_label_for_log}."
            return 1
        fi

        log_info "    Contents of Source IP Set (${SRC_IP_SET_NAME}) for ${pod_label_for_log}:"
        ${EXEC_KIND} nft list set bridge filter "${SRC_IP_SET_NAME}" || echo "    Failed to list set ${SRC_IP_SET_NAME}"
        ${EXEC_KIND} nft list set bridge filter "${SRC_IP_SET_NAME}" | grep -qF "${EXPECTED_IP_FOR_SET_CHECK}" || \
            { log_error "❌ Set ${SRC_IP_SET_NAME} does not contain ${EXPECTED_IP_FOR_SET_CHECK} for ${pod_label_for_log}."; return 1; }
    fi
    
    log_success "✔️ Rules and sets for ${expected_chain_name} (${pod_label_for_log}) checked."
    return 0
}

TEST_NAME=$(cat "${SCENARIO_DIR}/test.def")

log_info "🚀 Starting E2E Test: ${TEST_NAME}"

${KUBECTL} apply -f "${NAD_FILE}"
log_info "🔩 Applying Multi NetworkPolicy (select app=foo): ${MNP_FILE}"
${KUBECTL} apply -f "${MNP_FILE}"
log_info "🔩 Applying Initial Pod (label app=bar): ${POD_INITIAL_FILE}"
${KUBECTL} apply -f "${POD_INITIAL_FILE}"

log_info "⏳ Waiting for pod ${TARGET_POD_NAME} to be ready with initial label..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${POD_NAMESPACE}" --timeout=240s
TARGET_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${POD_NAMESPACE}")
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

log_info "🔎 === Checking Initial Status (Because it does NOT match Multi Network Policy) ==="
log_info "🔎 [Initial] Checking for ABSENCE of JUMP Ingress for MAC ${TARGET_POD_MAC_GLOBAL}..."
JUMP_RULE_INGRESS_INITIAL=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump KUBE_MULTI_INGRESS_" || echo "NOT_FOUND")
if [[ "$JUMP_RULE_INGRESS_INITIAL" != "NOT_FOUND" ]]
then
    log_error "❌ [Initial] JUMP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} WAS found, but it shouldn't have been."
    echo "Rule found: $JUMP_RULE_INGRESS_INITIAL"
    exit 1
fi
log_success "✔️ [Initial] No JUMP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} found, as expected."

log_info "🔩 Updating Pod label to app=foo: ${POD_UPDATED_FILE}"
${KUBECTL} apply -f "${POD_UPDATED_FILE}"
log_info "⏳ Waiting for controller to process update of Network Policy (30 seconds)..."
sleep 30

EXPECTED_CHAIN_SUFFIX_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${POD_NAMESPACE}" "${TARGET_POD_NAME}")
EXPECTED_INGRESS_CHAIN_NAME="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_GLOBAL}"
CIDR_DEFINED_IN_MNP="192.168.100.20/32" 
PORT_DEFINED_IN_MNP="80"

log_info "🔎 === Checking Status After Label Update (Pod NOW matches MultiNetworkPolicy) ==="
verify_ingress_rules_for_pod "${TARGET_POD_MAC_GLOBAL}" "${EXPECTED_INGRESS_CHAIN_NAME}" "${CIDR_DEFINED_IN_MNP}" "${PORT_DEFINED_IN_MNP}" "${TARGET_POD_NAME}" || exit 1

CONTROLLER_POD_NAME=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME" ]]
then
    log_info "🔎 [Post-Update] Checking NftPodChainMetadataCache for ${TARGET_POD_NAME}..."
    EXPECTED_CACHE_KEY_INGRESS="${EXPECTED_CHAIN_SUFFIX_GLOBAL}_ingress"
    
    CACHE_LOG_INGRESS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" | \
        grep "PolicyIngressRuleCount: 1" | grep "PolicyEgressRuleCount: 0" | grep "IsIsolationChain:false" | tail -n 1 || echo "")
        
    if [[ -z "$CACHE_LOG_INGRESS" ]]
    then
        log_error "❌ [Post-Update] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} missing or incorrect."
        ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" || echo "(no log for the key)"
        exit 1
    fi
    log_success "✔️ [Post-Update] Cache Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} found and correct."
else
    log_warn "⚠️ [Post-Update] Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
