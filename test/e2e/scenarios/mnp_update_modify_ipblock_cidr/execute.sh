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
POD_FILE="${SCENARIO_DIR}/01_target_pod.yaml"
MNP_INITIAL_FILE="${SCENARIO_DIR}/02_mnp_initial_cidr.yaml"
MNP_UPDATED_FILE="${SCENARIO_DIR}/03_mnp_updated_cidr.yaml"

TARGET_POD_NAME="target-pod-cidr-update"
TARGET_POD_NAMESPACE="default"
MNP_NAME="mnp-cidr-update-test" 

POLICY_FOR_NAD_NAME="e2e-test-bridge"
POLICY_FOR_NAD_NAMESPACE_REF="default"

NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"

TARGET_POD_MAC_GLOBAL=""


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
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_UPDATED_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_INITIAL_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${POD_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"
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
                      jq -r --arg NAD_NAME "${POLICY_FOR_NAD_NAMESPACE_REF}/${POLICY_FOR_NAD_NAME}" '.[] | select(.name == $NAD_NAME or .name == env.POLICY_FOR_NAD_NAME) | .mac' 2>/dev/null || echo "")
        if [[ -z "$mac_address" ]]; then
             mac_address=$(${KUBECTL} get pod "$pod_name" -n "$pod_ns" -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/network-status}' 2>/dev/null | \
                      jq -r --arg NAD_NAME_NO_NS "${POLICY_FOR_NAD_NAME}" '.[] | select(.name == $NAD_NAME_NO_NS) | .mac' 2>/dev/null || echo "")
        fi

        if [[ -n "$mac_address" ]]
        then
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

TEST_NAME=`cat test.def`

log_info "🚀 Starting E2E Test: ${TEST_NAME}"

log_info "🔩 Applying NetworkAttachementDefinition: ${NAD_FILE}"
${KUBECTL} apply -f "${NAD_FILE}"

log_info "🔩 Applying Pod: ${POD_FILE}"
${KUBECTL} apply -f "${POD_FILE}"
log_info "⏳ Waiting for pod ${TARGET_POD_NAMESPACE}/${TARGET_POD_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${TARGET_POD_NAMESPACE}" --timeout=120s
log_success "✔️ Pod ${TARGET_POD_NAMESPACE}/${TARGET_POD_NAME} is ready."


TARGET_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${TARGET_POD_NAMESPACE}")
if [[ -z "$TARGET_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address of pod ${TARGET_POD_NAME} not found. Aborting."
    exit 1
fi

sleep 15s

log_info "🔩 Applying Initial MultiNetworkPolicy: ${MNP_INITIAL_FILE}"
${KUBECTL} apply -f "${MNP_INITIAL_FILE}"

log_info "⏳ Waiting for mnp-nft-bridge controller to process changes (15 seconds)..."
sleep 15s

# --- Checks ---
log_info "🔎 Starting nftables checks..."
KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")

if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Could not get container ID from Kind's control plane."
    exit 1
fi

# 1. Find the pod chain (KUBE_MULTI_INGRESS_<hash>) through the JUMP rule
log_info "🔎 1. Checking JUMP rule in KUBE_MULTI_INGRESS chain for MAC ${TARGET_POD_MAC_GLOBAL} and getting pod chain name..."
JUMP_RULE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump KUBE_MULTI_INGRESS_")

if [[ -z "$JUMP_RULE_OUTPUT" ]]
then
    log_error "❌ JUMP rule for MAC ${TARGET_POD_MAC_GLOBAL} NOT found in KUBE_MULTI_INGRESS chain."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
    exit 1
fi

POD_CHAIN_NAME=$(echo "$JUMP_RULE_OUTPUT" | awk '{for(i=1;i<=NF;i++) if($i=="jump") print $(i+1)}' | tr -d '\r' | tr -d '\n')

if [[ -z "$POD_CHAIN_NAME" || "$POD_CHAIN_NAME" != KUBE_MULTI_INGRESS_* ]]
then
    log_error "❌ Unable to extract pod chain name from JUMP rule: '${JUMP_RULE_OUTPUT}'"
    exit 1
fi
log_success "✔️ JUMP rule found. Pod chain: ${POD_CHAIN_NAME}"

# 2. Check if the pod chain exists
log_info "🔎 2. Checking if chain ${POD_CHAIN_NAME} exists..."
POD_CHAIN_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter ${POD_CHAIN_NAME})

if [[ -n ${POD_CHAIN_OUTPUT} ]]
then
    log_success "✔️ Chain ${POD_CHAIN_NAME} found."
else
    log_error "❌ Chain ${POD_CHAIN_NAME} NOT found (inconsistency with JUMP rule)."
    ${EXEC_KIND} nft list ruleset
    exit 1
fi

# 3. Drop rule for target-pod MAC in KUBE_MULTI_INGRESS chain after jump rule.
log_info "🔎 3. Checking the PRESENCE of a DROP rule in the KUBE_MULTI_INGRESS chain for MAC ${TARGET_POD_MAC_GLOBAL}..."
DROP_RULE_FOUND=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} drop")
if [[ -n "$DROP_RULE_FOUND" ]]
then
    log_success "✔️ DROP rule found: ${DROP_RULE_FOUND}"
else
    log_error "❌ DROP rule for MAC ${TARGET_POD_MAC_GLOBAL} NOT found in KUBE_MULTI_INGRESS chain."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
    exit 1
fi

# 4. Check Sets and Accept Rules within the pod chain
EXPECTED_INITIAL_CIDR="10.0.0.0/24"
EXPECTED_PORT="8000"

log_info "🔎 4. Checking rules and sets within chain ${POD_CHAIN_NAME} for starting CIDR..."
POD_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${POD_CHAIN_NAME}")

RULE_LINE_INITIAL=$(echo "$POD_CHAIN_RULES" | grep "ip saddr ${EXPECTED_INITIAL_CIDR}" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
if [[ -z "$RULE_LINE_INITIAL" ]]
then
    log_error "❌ [Initial] ACCEPT rule for (IP Mask ${EXPECTED INITIAL CIDR} + TCP Port Set) NOT found in ${POD_CHAIN_NAME}."
    echo "$POD_CHAIN_RULES"
    exit 1
fi
TCP_PORT_SET_NAME_INITIAL=$(echo "$RULE_LINE_INITIAL" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | tr -d '\r' | tr -d '\n')
log_success "✔️ [Initial] ACCEPT rule for initial CIDR found."

# 5. Apply the update to MNP
log_info "🔩 Applying Updated MNP (Modified CIDR): ${MNP_UPDATED_FILE}"
${KUBECTL} apply -f "${MNP_UPDATED_FILE}"
log_info "⏳ Waiting for mnp-nft-bridge controller to process update (15 seconds)..."
sleep 15s

# 6. Check the status after the update
log_info "🔎 Checking nftables status AFTER MultiNetworkPolicy update..."
POD_CHAIN_RULES_UPDATED=$(${EXEC_KIND} nft list chain bridge filter "${POD_CHAIN_NAME}")
EXPECTED_UPDATED_CIDR="10.0.1.0/24"

log_info "🔎 6a. Checking if Ingress rule was UPDATED to new CIDR ${EXPECTED_UPDATED_CIDR}..."
RULE_LINE_UPDATED=$(echo "$POD_CHAIN_RULES_UPDATED" | grep "ip saddr ${EXPECTED_UPDATED_CIDR}" | grep "tcp dport @${TCP_PORT_SET_NAME_INITIAL}" | grep "accept" | head -n1)
if [[ -z "$RULE_LINE_UPDATED" ]]
then
    log_error "❌ [Updated] ACCEPT rule for (IP Mask ${EXPECTED_UPDATED_CIDR} + TCP Port Set) NOT found."
    echo "$POD_CHAIN_RULES_UPDATED"
    exit 1
fi
log_success "✔️ [Updated] ACCEPT rule with new CIDR found."

log_info "🔎 6b. Checking if rule with OLD CIDR (${EXPECTED_INITIAL_CIDR}) NO LONGER exists..."
RULE_LINE_OLD_CIDR_AFTER_UPDATE=$(echo "$POD_CHAIN_RULES_UPDATED" | grep "ip saddr ${EXPECTED_INITIAL_CIDR}" || echo "NOT_FOUND")
if [[ "$RULE_LINE_OLD_CIDR_AFTER_UPDATE" == "NOT_FOUND" ]]
then
    log_success "✔️ [Updated] Rule with OLD CIDR ${EXPECTED_INITIAL_CIDR} not found, as expected."
else
    log_error "❌ [Updated] Rule with OLD CIDR ${EXPECTED_INITIAL_CIDR} STILL EXISTS, but it shouldn't."
    echo "$POD_CHAIN_RULES_UPDATED"
    exit 1
fi

log_info "✅ Test finished: ${TEST_NAME}"