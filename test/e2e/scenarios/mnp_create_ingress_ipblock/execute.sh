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

set -eo pipefail # Exit in case of error

exit_code=0
trap 'exit_code=$?; cleanup; exit $exit_code' EXIT

# Scenario Variables
export SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HACK_DIR="${SCENARIO_DIR}/../../../../hack"

NAD_FILE="${SCENARIO_DIR}/00_nad_bridge.yaml"
POD_FILE="${SCENARIO_DIR}/01_target_pod.yaml"
MNP_FILE="${SCENARIO_DIR}/02_mnp_allow_ingress.yaml"

TARGET_POD_NAME="target-pod-ipblock-test"
TARGET_POD_NAMESPACE="default"
POLICY_FOR_NAD_NAME="e2e-test-bridge"
POLICY_FOR_NAD_NAMESPACE="default"

NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"

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
                      jq -r --arg NAD_NAME "${POLICY_FOR_NAD_NAMESPACE}/${POLICY_FOR_NAD_NAME}" '.[] | select(.name == $NAD_NAME or .name == env.POLICY_FOR_NAD_NAME) | .mac' 2>/dev/null || echo "")
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

TEST_NAME=`cat test.def`

log_info "🚀 Starting E2E Test: ${TEST_NAME}"

log_info "🔩 Applying NetworkAttachmentDefinition: ${NAD_FILE}"
${KUBECTL} apply -f "${NAD_FILE}"

log_info "🔩 Applying Pod: ${POD_FILE}"
${KUBECTL} apply -f "${POD_FILE}"
log_info "⏳ Waiting for ${TARGET_POD_NAMESPACE}/${TARGET_POD_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${TARGET_POD_NAMESPACE}" --timeout=180s
log_success "✔️ Pod ${TARGET_POD_NAMESPACE}/${TARGET_POD_NAME} is ready."


TARGET_POD_MAC=$(get_pod_mac "${TARGET_POD_NAME}" "${TARGET_POD_NAMESPACE}")
if [[ -z "$TARGET_POD_MAC" ]]; then
    log_error "❌ MAC Address for pod ${TARGET_POD_NAME} not found. Aborting."
    exit 1
fi

sleep 15s

log_info "🔩 Applying MultiNetworkPolicy: ${MNP_FILE}"
${KUBECTL} apply -f "${MNP_FILE}"

log_info "⏳ Waiting for the controller mnp-nft-bridge to process the changes (15 seconds)..."
sleep 15s

# --- Checkups ---
log_info "🔎 Starting nftables checking..."
KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")

if [[ -z "$KIND_CONTROL_PLANE_ID" ]]; then
    log_error "❌ Failed to obtain container ID for Kind's control-plane."
    exit 1
fi

# 1. Find pod's chain (KUBE_MULTI_INGRESS_<hash>) from JUMP rule
log_info "🔎 1. Checking JUMP rule in chain KUBE_MULTI_INGRESS for MAC ${TARGET_POD_MAC} and getting pod's chain name..."
JUMP_RULE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC} jump KUBE_MULTI_INGRESS_")

if [[ -z "$JUMP_RULE_OUTPUT" ]]; then
    log_error "❌ JUMP rule for MAC ${TARGET_POD_MAC} NOT found in chain KUBE_MULTI_INGRESS."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
    exit 1
fi

# Extract pod's chain name from JUMP rule output
POD_CHAIN_NAME=$(echo "$JUMP_RULE_OUTPUT" | awk '{for(i=1;i<=NF;i++) if($i=="jump") print $(i+1)}' | tr -d '\r' | tr -d '\n')

if [[ -z "$POD_CHAIN_NAME" || "$POD_CHAIN_NAME" != KUBE_MULTI_INGRESS_* ]]; then
    log_error "❌ Unable to extract pod chain name from JUMP rule: '${JUMP_RULE_OUTPUT}'"
    exit 1
fi
log_success "✔️ JUMP rule found. Pod chain: ${POD_CHAIN_NAME}"

#2. Check if the pod chain exists (already implied if the jump exists, but good for clarity)
log_info "🔎 2. Checking if chain ${POD_CHAIN_NAME} exists..."
POD_CHAIN_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter ${POD_CHAIN_NAME})

if [[ -n ${POD_CHAIN_OUTPUT} ]]; then
    log_success "✔️ Chain ${POD_CHAIN_NAME} found."
else
    log_error "❌ Chain ${POD_CHAIN_NAME} NOT found (inconsistency with JUMP rule)."
    ${EXEC_KIND} nft list ruleset
    exit 1
fi

# 3. Drop rule for target-pod MAC in KUBE_MULTI_INGRESS chain after jump rule.
log_info "🔎 3. Checking DROP rule in chain KUBE MULTI INGRESS for MAC ${TARGET_POD_MAC}..."
DROP_RULE_FOUND=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC} drop")
if [[ -n "$DROP_RULE_FOUND" ]]; then
    log_success "✔️ DROP rule found: ${DROP_RULE_FOUND}"
else
    log_error "❌ DROP rule for MAC ${TARGET_POD_MAC} NOT found in chain KUBE_MULTI_INGRESS."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS
    exit 1
fi

# 4. Check Sets and ACCEPT rules within the pod chain
EXPECTED_SRC_IP_IN_SET="192.168.100.50"
EXPECTED_SRC_IP_MASK_RULE_CIDR="172.17.0.0/16"
EXPECTED_TCP_PORT="80"
EXPECTED_UDP_PORT="5300"

log_info "🔎 4. Checking rules and sets inside chain ${POD_CHAIN_NAME}..."
POD_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${POD_CHAIN_NAME}")

# Check rule for Set IP + TCP Port
RULE_SET_IP_TCP=$(echo "$POD_CHAIN_RULES" | grep "ip saddr @mnp-src-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" || echo "")

if [[ -z "$RULE_SET_IP_TCP" ]]; then
    log_error "❌ ACCEPT rule for (IP Set + TCP Port Set) NOT found in ${POD_CHAIN_NAME}."
    echo "$POD_CHAIN_RULES"
    exit 1
fi
SRC_IP_SET_NAME_TCP=$(echo "$RULE_SET_IP_TCP" | grep -o 'mnp-src-ip-[a-f0-9]\{16\}' | tr -d '\r' | tr -d '\n')
TCP_PORT_SET_NAME=$(echo "$RULE_SET_IP_TCP" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | tr -d '\r' | tr -d '\n')
log_success "✔️ ACCEPT rule (IP Set: ${SRC_IP_SET_NAME_TCP}, TCP Port Set: ${TCP_PORT_SET_NAME}) found."

# Check contents of Source IP Set
SET_CONTENT_SRC_IP=$(${EXEC_KIND} nft list set bridge filter "${SRC_IP_SET_NAME_TCP}" 2>/dev/null)
if ! echo "$SET_CONTENT_SRC_IP" | grep -q "${EXPECTED_SRC_IP_IN_SET}"; then
    log_error "❌ Set ${SRC_IP_SET_NAME_TCP} DOES NOT contain ${EXPECTED_SRC_IP_IN_SET}."
    echo "$SET_CONTENT_SRC_IP"
    exit 1
fi
log_success "✔️ Set ${SRC_IP_SET_NAME_TCP} contains ${EXPECTED_SRC_IP_IN_SET}."

# Check contents of TCP Port Set
SET_CONTENT_TCP_PORT=$(${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME}" 2>/dev/null)
if ! echo "$SET_CONTENT_TCP_PORT" | grep -q "${EXPECTED_TCP_PORT}"; then
    log_error "❌ Set ${TCP_PORT_SET_NAME} DOES NOT contain ${EXPECTED_TCP_PORT}."
    echo "$SET_CONTENT_TCP_PORT"
    exit 1
fi
log_success "✔️ Set ${TCP_PORT_SET_NAME} contains ${EXPECTED_TCP_PORT}."


# Check rule for Set IP + UDP Port
RULE_SET_IP_UDP=$(echo "$POD_CHAIN_RULES" | grep "ip saddr @${SRC_IP_SET_NAME_TCP}" | grep "udp dport @mnp-udp-port-" | grep "accept" || echo "") # Reutiliza SRC_IP_SET_NAME_TCP
if [[ -z "$RULE_SET_IP_UDP" ]]; then
    log_error "❌ ACCEPT rule for (IP Set + UDP Port Set) NOT found in ${POD_CHAIN_NAME}."
    echo "$POD_CHAIN_RULES"
    exit 1
fi
UDP_PORT_SET_NAME=$(echo "$RULE_SET_IP_UDP" | grep -o 'mnp-udp-port-[a-f0-9]\{16\}' | tr -d '\r' | tr -d '\n')
log_success "✔️ ACCEPT rule (IP Set: ${SRC_IP_SET_NAME_TCP}, UDP Port Set: ${UDP_PORT_SET_NAME}) found."

# Check contents of UDP Port Set
SET_CONTENT_UDP_PORT=$(${EXEC_KIND} nft list set bridge filter "${UDP_PORT_SET_NAME}" 2>/dev/null)
if ! echo "$SET_CONTENT_UDP_PORT" | grep -q "${EXPECTED_UDP_PORT}"; then
    log_error "❌ Set ${UDP_PORT_SET_NAME} DOES NOT contain ${EXPECTED_UDP_PORT}."
    echo "$SET_CONTENT_UDP_PORT"
    exit 1
fi
log_success "✔️ Set ${UDP_PORT_SET_NAME} contains ${EXPECTED_UDP_PORT}."


# Check rule for Mask IP + TCP Port
RULE_MASK_IP_TCP=$(echo "$POD_CHAIN_RULES" | grep "ip saddr ${EXPECTED_SRC_IP_MASK_RULE_CIDR}" | grep "tcp dport @${TCP_PORT_SET_NAME}" | grep "accept" || echo "")
if [[ -z "$RULE_MASK_IP_TCP" ]]; then
    log_error "❌ ACCEPT rule for (IP Mask ${EXPECTED_SRC_IP_MASK_RULE_CIDR} + TCP Port Set ${TCP_PORT_SET_NAME}) NOT found in ${POD_CHAIN_NAME}."
    echo "$POD_CHAIN_RULES"
    exit 1
fi
log_success "✔️ ACCEPT rule (IP Mask ${EXPECTED_SRC_IP_MASK_RULE_CIDR} + TCP Port Set ${TCP_PORT_SET_NAME}) found."

# Check rule for Mask IP + UDP Port
RULE_MASK_IP_UDP=$(echo "$POD_CHAIN_RULES" | grep "ip saddr ${EXPECTED_SRC_IP_MASK_RULE_CIDR}" | grep "udp dport @${UDP_PORT_SET_NAME}" | grep "accept" || echo "")
if [[ -z "$RULE_MASK_IP_UDP" ]]; then
    log_error "❌ ACCEPT rule for (IP Mask ${EXPECTED_SRC_IP_MASK_RULE_CIDR} + UDP Port Set ${UDP_PORT_SET_NAME}) NOT found in ${POD_CHAIN_NAME}."
    echo "$POD_CHAIN_RULES"
    exit 1
fi
log_success "✔️ ACCEPT rule (IP Mask ${EXPECTED_SRC_IP_MASK_RULE_CIDR} + UDP Port Set ${UDP_PORT_SET_NAME}) found."


# 5. NftPodChainMetadataCache contains entry for this chain/pod/policy.
log_info "🔎 5. Checking NftPodChainMetadataCache in controller's log..."
CONTROLLER_POD_NAME=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -z "$CONTROLLER_POD_NAME" ]]; then
    log_warn "⚠️ Not able to find controller pod mnp-nft-bridge. Jumping NftPodChainMetadataCache check."
else
    # The cache key is chainSuffix + "_" + chainType. The chainSuffix is part of the POD_CHAIN_NAME.
    CHAIN_SUFFIX_FROM_NAME=$(echo "${POD_CHAIN_NAME}" | sed 's/KUBE_MULTI_INGRESS_//')
    EXPECTED_CACHE_KEY="${CHAIN_SUFFIX_FROM_NAME}_ingress"

    # Look for logs that indicate addition/update of metadata for this key
    CACHE_LOG_FOUND=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep -E "(Added/Updated metadata|Storing/Updating metadata|Updated/Ensured metadata cache)" | \
        grep "for key: ${EXPECTED_CACHE_KEY}" || echo "")

    if [[ -n "$CACHE_LOG_FOUND" ]]; then
        log_success "✔️ Entry for key ${EXPECTED_CACHE_KEY} found in NftPodChainMetadataCache's controller log."
        echo "Log found:"
        echo "$CACHE_LOG_FOUND" | head -n 1 # Show only the 1st line
    else
        log_error "❌ Entry for key ${EXPECTED_CACHE_KEY} NOT found in NftPodChainMetadataCache's controller log."
        log_info "   Contoller logs (last 5 min) for NftPodChainMetadataCache:"
        ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | grep "nftPodChainMetadataCache" || echo "   (No relevant log found)"
    fi
fi

log_info "✅ Test finished: ${TEST_NAME}"
