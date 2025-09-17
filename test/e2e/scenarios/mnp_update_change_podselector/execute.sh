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
POD_A_FILE="${SCENARIO_DIR}/01_pod_a_old_target.yaml"
POD_B_FILE="${SCENARIO_DIR}/02_pod_b_new_target.yaml"
MNP_SELECTS_OLD_FILE="${SCENARIO_DIR}/03_mnp_selects_old_target.yaml"
MNP_SELECTS_NEW_FILE="${SCENARIO_DIR}/04_mnp_selects_new_target.yaml"

POD_A_NAME="pod-a-is-old-target"
POD_B_NAME="pod-b-is-new-target"
POD_NAMESPACE="default"

MNP_NAME="mnp-podselector-change-test"
MNP_NAMESPACE="default"

POLICY_FOR_NAD_NAME="e2e-test-bridge"
POLICY_FOR_NAD_NAMESPACE_REF="default"

NFT_CONTROLLER_NAMESPACE="kube-system"
NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"

POD_A_MAC_GLOBAL=""
POD_B_MAC_GLOBAL=""
EXPECTED_CHAIN_SUFFIX_POD_A_GLOBAL=""
EXPECTED_INGRESS_CHAIN_NAME_POD_A="" # Defined after we get suffix
EXPECTED_CHAIN_SUFFIX_POD_B_GLOBAL=""
# EXPECTED_INGRESS_CHAIN_NAME_POD_B will be defined later


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
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_SELECTS_NEW_FILE}"
    # MNP_SELECTS_OLD_FILE is replaced by NEW_FILE, so there's no need to explicitly delete it if NEW was applied.
    # But to be safe, we can try deleting both.
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_SELECTS_OLD_FILE}"
    log_info "  Waiting for controller to process MltiNetworkPolicy deletion (15s)..."
    sleep 15

    ${KUBECTL} delete --ignore-not-found=true -f "${POD_A_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${POD_B_FILE}"
    log_info "  Waiting for controller to process Pods deletion (15s)..."
    sleep 15

    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"

    log_info "  Checking if ruleset is clean after cleanup..."
    KIND_CONTROL_PLANE_ID_CLEANUP=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
    if [[ -n "$KIND_CONTROL_PLANE_ID_CLEANUP" ]]; then
        log_info "  Waiting a bit more for reconciler (10s)..."
        sleep 10
        FINAL_RULESET=$(${EXEC_KIND} nft list ruleset bridge)

        ERROR_FOUND_CLEANUP=0
        CHAIN_PATTERN_A_CLEANUP=""
        if [[ -n "$EXPECTED_CHAIN_SUFFIX_POD_A_GLOBAL" ]]; then
            CHAIN_PATTERN_A_CLEANUP="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_POD_A_GLOBAL}"
            if echo "$FINAL_RULESET" | grep -qF "chain ${CHAIN_PATTERN_A_CLEANUP}"; then
                log_error "❌ CLEANUP ERROR: Chain ${CHAIN_PATTERN_A_CLEANUP} (for Pod A) still exists!"
                ERROR_FOUND_CLEANUP=1
            fi
        fi
        CHAIN_PATTERN_B_CLEANUP=""
        if [[ -n "$EXPECTED_CHAIN_SUFFIX_POD_B_GLOBAL" ]]; then
            CHAIN_PATTERN_B_CLEANUP="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_POD_B_GLOBAL}"
            if echo "$FINAL_RULESET" | grep -qF "chain ${CHAIN_PATTERN_B_CLEANUP}"; then
                log_error "❌ CLEANUP ERROR: Chain ${CHAIN_PATTERN_B_CLEANUP} (for Pod B) still exists!"
                ERROR_FOUND_CLEANUP=1
            fi
        fi

        if echo "$FINAL_RULESET" | grep -q "set mnp-"; then
            log_error "❌ CLEANUP ERROR: Sets 'mnp-' still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if [[ -n "$POD_A_MAC_GLOBAL" ]] && echo "$FINAL_RULESET" | grep -q "ether daddr ${POD_A_MAC_GLOBAL} jump"; then
            log_error "❌ CLEANUP ERROR: JUMP Ingress rule for POD A's MAC (${POD_A_MAC_GLOBAL}) still exists!"
            ERROR_FOUND_CLEANUP=1
        fi
        if [[ -n "$POD_B_MAC_GLOBAL" ]] && echo "$FINAL_RULESET" | grep -q "ether daddr ${POD_B_MAC_GLOBAL} jump"; then
            log_error "❌ CLEANUP ERROR: JUMP Ingress rule for POD B's MAC (${POD_B_MAC_GLOBAL}) still exists!"
            ERROR_FOUND_CLEANUP=1
        fi

        if [[ "$ERROR_FOUND_CLEANUP" -eq 1 ]]; then
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

verify_ingress_rules_for_pod() {
    local state_label="$1"
    local pod_mac="$2"
    local expected_chain_name="$3"
    local expected_cidr_param="$4"
    local expected_port="$5"
    local pod_label_for_log="$6"

    log_info "🔎 ${state_label} Checking JUMP Ingress for MAC ${pod_mac} for ${expected_chain_name} (${pod_label_for_log})..."
    JUMP_RULE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
        grep -F "ether daddr ${pod_mac} jump ${expected_chain_name}" || echo "NOT_FOUND")
    if [[ "$JUMP_RULE_OUTPUT" == "NOT_FOUND" ]]; then
        log_error "❌ ${state_label} JUMP Ingress rule for MAC ${pod_mac} for ${expected_chain_name} (${pod_label_for_log}) NOT found."
        ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS; return 1
    fi
    log_success "✔️ ${state_label} JUMP Ingress rule for ${expected_chain_name} (${pod_label_for_log}) found."

    log_info "🔎 ${state_label} Checking the PRESENCE of DROP Ingress for MAC ${pod_mac} (${pod_label_for_log}) in KUBE_MULTI_INGRESS..."
    DROP_RULE_BASE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
        grep -F "ether daddr ${pod_mac} drop" || echo "NOT_FOUND")
    if [[ "$DROP_RULE_BASE_OUTPUT" != "NOT_FOUND" ]]
    then
        log_success "✔️ ${state_label} Ingress DROP rule for MAC ${pod_mac} (${pod_label_for_log}) in KUBE_MULTI_INGRESS found, as expected."
    else
        log_error "❌ ${state_label} Ingress DROP rule for MAC ${pod_mac} (${pod_label_for_log}) was NOT found in KUBE_MULTI_INGRESS, but it should have been."
        ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS; return 1
    fi

    log_info "🔎 ${state_label} Checking rules within the chain ${expected_chain_name} (${pod_label_for_log})..."
    INGRESS_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${expected_chain_name}")

    IP_FOR_SET_CHECK="${expected_cidr_param%%/*}"
    IS_SINGLE_IP=false
    if [[ "$expected_cidr_param" == *"/"* ]]; then
        MASK_PART="${expected_cidr_param#*/}"
        if [[ "$MASK_PART" == "32" ]]; then IS_SINGLE_IP=true; fi
    else
        IS_SINGLE_IP=true; IP_FOR_SET_CHECK="$expected_cidr_param"
    fi

    RULE_LINE=""
    if [[ "$IS_SINGLE_IP" == true ]]; then
        RULE_LINE=$(echo "$INGRESS_CHAIN_RULES" | grep "ip saddr @mnp-src-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    else
        RULE_LINE=$(echo "$INGRESS_CHAIN_RULES" | grep -F "ip saddr ${expected_cidr_param}" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
    fi

    if [[ -z "$RULE_LINE" ]]
    then
        log_error "❌ ${state_label} Ingress rule (Expected: ${expected_cidr_param} -> TCP/${expected_port}) not found in chain ${expected_chain_name} (${pod_label_for_log})."
        echo "$INGRESS_CHAIN_RULES"
        return 1
    fi

    TCP_PORT_SET_NAME=$(echo "$RULE_LINE" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
    if [[ -z "$TCP_PORT_SET_NAME" ]]
    then
        log_error "❌ ${state_label} Failed to fetch TCP Ingress port set name for ${pod_label_for_log}."
        return 1
    fi

    ${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME}" | grep -qE "(^|[[:space:],{])${expected_port}([[:space:],}]|$)" || \
        { log_error "❌ ${state_label} Set Ingress ${TCP_PORT_SET_NAME} does not contain port ${expected_port} for ${pod_label_for_log}."; return 1; }

    if [[ "$IS_SINGLE_IP" == true ]]; then
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
    local expected_chain_name_if_existed="$2"
    local pod_label_for_log="$3"

    log_info "🔎 Checking for ABSENCE of JUMP Ingress for MAC ${pod_mac} (${pod_label_for_log}) for chain ${expected_chain_name_if_existed}..."
    JUMP_RULE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
        grep -F "ether daddr ${pod_mac} jump ${expected_chain_name_if_existed}" || echo "NOT_FOUND")
    if [[ "$JUMP_RULE_OUTPUT" != "NOT_FOUND" ]]
    then
        log_error "❌ JUMP Ingress rule for MAC ${pod_mac} (${pod_label_for_log}) for ${expected_chain_name_if_existed} WAS found, but it shouldn't have been."
        echo "Rule found: $JUMP_RULE_OUTPUT"
        return 1
    fi
    log_success "✔️ No JUMP Ingress rule for MAC ${pod_mac} (${pod_label_for_log}) for ${expected_chain_name_if_existed} found, as expected."

    if [[ -n "$expected_chain_name_if_existed" ]]
    then
        log_info "🔎 Checking for ABSENCE of chain ${expected_chain_name_if_existed} (${pod_label_for_log})..."
        if ${EXEC_KIND} nft list chain bridge filter "${expected_chain_name_if_existed}" > /dev/null 2>&1; then
            log_error "❌ Chain ${expected_chain_name_if_existed} (${pod_label_for_log}) WAS found, but it shouldn't have been."
            return 1
        fi
        log_success "✔️ Chain ${expected_chain_name_if_existed} (${pod_label_for_log}) not found, as expected."
    fi
    return 0
}


TEST_NAME=$(cat "${SCENARIO_DIR}/test.def")

log_info "🚀 Starting E2E Test: ${TEST_NAME}"

${KUBECTL} apply -f "${NAD_FILE}"
${KUBECTL} apply -f "${POD_A_FILE}"
${KUBECTL} apply -f "${POD_B_FILE}"

log_info "⏳ Waiting for pod ${POD_A_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${POD_A_NAME}" -n "${POD_NAMESPACE}" --timeout=180s
POD_A_MAC_GLOBAL=$(get_pod_mac "${POD_A_NAME}" "${POD_NAMESPACE}")
if [[ -z "$POD_A_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${POD_A_NAME} not found."
    exit 1
fi

log_info "⏳ Waiting for pod ${POD_B_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${POD_B_NAME}" -n "${POD_NAMESPACE}" --timeout=180s
POD_B_MAC_GLOBAL=$(get_pod_mac "${POD_B_NAME}" "${POD_NAMESPACE}")
if [[ -z "$POD_B_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${POD_B_NAME} not found."
    exit 1
fi

sleep 15s
log_info "🔩 Applying Initial MultiNetworkPolicy (selecting ${POD_A_NAME}): ${MNP_SELECTS_OLD_FILE}"
${KUBECTL} apply -f "${MNP_SELECTS_OLD_FILE}"
log_info "⏳ Waiting for controller to process Initial MultiNetworkPolicy (30 seconds)..."
sleep 30

KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Could not get Kind's control-plane ID."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX_POD_A_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${POD_NAMESPACE}" "${POD_A_NAME}")
EXPECTED_INGRESS_CHAIN_NAME_POD_A="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_POD_A_GLOBAL}"
CIDR_FOR_POLICY="172.20.0.0/24"
PORT_FOR_POLICY="80"

log_info "🔎 === Checking Initial State (MultiNetworkPolicy selects ${POD_A_NAME}) ==="
verify_ingress_rules_for_pod "[Initial-PodA]" "${POD_A_MAC_GLOBAL}" "${EXPECTED_INGRESS_CHAIN_NAME_POD_A}" "${CIDR_FOR_POLICY}" "${PORT_FOR_POLICY}" "${POD_A_NAME}" || exit 1

EXPECTED_CHAIN_SUFFIX_POD_B_POTENTIAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${POD_NAMESPACE}" "${POD_B_NAME}")
EXPECTED_INGRESS_CHAIN_NAME_POD_B_POTENTIAL="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_POD_B_POTENTIAL}"
verify_NO_ingress_rules_for_pod "${POD_B_MAC_GLOBAL}" "${EXPECTED_INGRESS_CHAIN_NAME_POD_B_POTENTIAL}" "${POD_B_NAME}" || exit 1

CONTROLLER_POD_NAME_INITIAL=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME_INITIAL" ]]
then
    log_info "🔎 [Initial] Checking NftPodChainMetadataCache for ${POD_A_NAME}..."
    EXPECTED_CACHE_KEY_POD_A="${EXPECTED_CHAIN_SUFFIX_POD_A_GLOBAL}_ingress"
    LOG_SINCE_DURATION_INITIAL="10m"
    sleep 5 # Increase window and sleep

    ALL_POD_A_CACHE_LOGS_INITIAL=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_INITIAL}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION_INITIAL} | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_POD_A}")

    LATEST_VALID_POD_A_LOG_INITIAL=$(echo "$ALL_POD_A_CACHE_LOGS_INITIAL" | grep "Added/Updated" | \
        grep "PolicyName: ${MNP_NAMESPACE}/${MNP_NAME}" | grep "PolicyIngressRuleCount: 1" | grep "IsIsolationChain:false" | tail -n 1 || echo "")
    if [[ -z "$LATEST_VALID_POD_A_LOG_INITIAL" ]]
    then
        log_error "❌ [Initial] Cache entry for ${POD_A_NAME} (key ${EXPECTED_CACHE_KEY_POD_A}) missing or incorrect."
        echo "DEBUG: Logs for Pod A key (${EXPECTED_CACHE_KEY_POD_A}):"
        echo "${ALL_POD_A_CACHE_LOGS_INITIAL:- (No logs)}"
        exit 1;
    fi
    log_success "✔️ [Initial] Cache entry for ${POD_A_NAME} found."
else
    log_warn "⚠️ [Initial] Unable to verify NftPodChainMetadataCache."
fi

log_info "🔩 Applying Updated MultiNetworkPolicy (selecting ${POD_B_NAME}): ${MNP_SELECTS_NEW_FILE}"
${KUBECTL} apply -f "${MNP_SELECTS_NEW_FILE}"
log_info "⏳ Waiting for controller to process Initial MultiNetworkPolicy (30 seconds)..."
sleep 30

EXPECTED_CHAIN_SUFFIX_POD_B_GLOBAL=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${POD_NAMESPACE}" "${POD_B_NAME}")
EXPECTED_INGRESS_CHAIN_NAME_POD_B="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX_POD_B_GLOBAL}"

log_info "🔎 === Checking Status After Update (MultiNetworkPolicy selects ${POD_B_NAME}) ==="
verify_NO_ingress_rules_for_pod "${POD_A_MAC_GLOBAL}" "${EXPECTED_INGRESS_CHAIN_NAME_POD_A}" "${POD_A_NAME}" || exit 1
verify_ingress_rules_for_pod "[After-Update-PodB]" "${POD_B_MAC_GLOBAL}" "${EXPECTED_INGRESS_CHAIN_NAME_POD_B}" "${CIDR_FOR_POLICY}" "${PORT_FOR_POLICY}" "${POD_B_NAME}" || exit 1

CONTROLLER_POD_NAME_UPDATED=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -n "$CONTROLLER_POD_NAME_UPDATED" ]]
then
    log_info "🔎 [Updated] Checking NftPodChainMetadataCache for ${POD_B_NAME}..."
    EXPECTED_CACHE_KEY_POD_B="${EXPECTED_CHAIN_SUFFIX_POD_B_GLOBAL}_ingress"
    LOG_SINCE_DURATION_UPDATED="2m"
    sleep 5 # Smaller window, but enough for update logs

    ALL_POD_B_CACHE_LOGS_UPDATED=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_UPDATED}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION_UPDATED} | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_POD_B}")

    LATEST_VALID_POD_B_LOG_UPDATED=$(echo "$ALL_POD_B_CACHE_LOGS_UPDATED" | grep "Added/Updated" | \
        grep "PolicyName: ${MNP_NAMESPACE}/${MNP_NAME}" | grep "PolicyIngressRuleCount: 1" | grep "IsIsolationChain:false" | tail -n 1 || echo "")
    if [[ -z "$LATEST_VALID_POD_B_LOG_UPDATED" ]]
    then
        log_error "❌ [Updated] Cache entry for ${POD_B_NAME} (key ${EXPECTED_CACHE_KEY_POD_B}) not found or incorrect after MNP update."
        echo "DEBUG: Logs for Pod B key (${EXPECTED_CACHE_KEY_POD_B}):"
        echo "${ALL_POD_B_CACHE_LOGS_UPDATED:- (No logs)}"
        exit 1;
    fi
    log_success "✔️ [Updated] Cache entry for ${POD_B_NAME} found."

    # Check if the entry for POD A was DELETED
    EXPECTED_CACHE_KEY_POD_A_TO_DELETE="${EXPECTED_CHAIN_SUFFIX_POD_A_GLOBAL}_ingress"
    log_info "🔎 [Updated] Checking if metadata for ${POD_A_NAME} (key ${EXPECTED_CACHE_KEY_POD_A_TO_DELETE}) has been removed from cache..."

    LOGS_AFTER_MNP_UPDATE_FOR_POD_A_CHECK=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME_UPDATED}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=${LOG_SINCE_DURATION_UPDATED})

    DELETED_LOG_POD_A=$(echo "$LOGS_AFTER_MNP_UPDATE_FOR_POD_A_CHECK" | grep "nftPodChainMetadataCache" | grep "Deleted metadata" | grep "for key: ${EXPECTED_CACHE_KEY_POD_A_TO_DELETE}" | tail -n 1 || echo "NO_DELETE_LOG")

    if [[ "$DELETED_LOG_POD_A" == "NO_DELETE_LOG" ]]
    then
        log_warn "⚠️ [Updated] Deletion log for ${POD_A_NAME} metadata (key ${EXPECTED_CACHE_KEY_POD_A_TO_DELETE}) NOT found in recent logs. Checking for absence of recent Add/Update for this key..."
        RECENT_ADD_UPDATE_FOR_POD_A=$(echo "$LOGS_AFTER_MNP_UPDATE_FOR_POD_A_CHECK" | grep "nftPodChainMetadataCache" | grep "Added/Updated" | grep "for key: ${EXPECTED_CACHE_KEY_POD_A_TO_DELETE}" || echo "NO_RECENT_ADD_UPDATE_FOR_POD_A")
        if [[ "$RECENT_ADD_UPDATE_FOR_POD_A" != "NO_RECENT_ADD_UPDATE_FOR_POD_A" ]]
        then
            log_error "❌ [Updated] Metadata for ${POD_A_NAME} (key ${EXPECTED_CACHE_KEY_POD_A_TO_DELETE}) appears to have been Added/Updated recently AFTER the MNP changed, which should not happen."
            echo "Add/Update log found: $RECENT_ADD_UPDATE_FOR_POD_A"
            exit 1
        else
            log_success "✔️ [Updated] No recent Add/Update for metadata of ${POD_A_NAME} (key ${EXPECTED_CACHE_KEY_POD_A_TO_DELETE}) and no explicit delete log found (may have been cleared before the log window, but NFTables state is correct)."
        fi
    else
        log_success "✔️ [Updated] Deletion log for metadata of ${POD_A_NAME} (key ${EXPECTED_CACHE_KEY_POD_A_TO_DELETE}) found."
    fi
else
    log_warn "⚠️ [Updated] Unable to verify NftPodChainMetadataCache."
fi

log_info "✅ Test finished: ${TEST_NAME}"
