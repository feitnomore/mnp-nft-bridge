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
NS_TARGET_FILE="${SCENARIO_DIR}/01_ns_target.yaml"
NS_CLIENT_ALPHA_FILE="${SCENARIO_DIR}/02_ns_client_alpha.yaml"
NS_CLIENT_BETA_FILE="${SCENARIO_DIR}/03_ns_client_beta.yaml"
TARGET_POD_FILE="${SCENARIO_DIR}/04_target_pod.yaml"
SOURCE_POD_ALPHA_FILE="${SCENARIO_DIR}/05_source_pod_alpha.yaml"
SOURCE_POD_BETA_FILE="${SCENARIO_DIR}/06_source_pod_beta.yaml"
DEST_POD_GAMMA_FILE="${SCENARIO_DIR}/07_dest_pod_gamma.yaml"
MNP_FILE="${SCENARIO_DIR}/08_mnp_complex.yaml"

TARGET_POD_NAME="target-pod-complex"
TARGET_POD_NAMESPACE="ns-complex-target"
MNP_NAME="complex-server-policy"
MNP_NAMESPACE="ns-complex-target"

SOURCE_POD_ALPHA_NAME="source-pod-alpha"
SOURCE_POD_ALPHA_NAMESPACE="ns-complex-target"

SOURCE_POD_BETA_NAME="source-pod-beta"
SOURCE_POD_BETA_NAMESPACE="ns-complex-client-alpha"

DEST_POD_GAMMA_NAME="dest-pod-gamma"
DEST_POD_GAMMA_NAMESPACE="ns-complex-client-beta"

POLICY_FOR_NAD_NAME="e2e-test-bridge"
POLICY_FOR_NAD_NAMESPACE_REF="default"

NFT_CONTROLLER_POD_LABEL="app=mnp-nft-bridge"
NFT_CONTROLLER_NAMESPACE="kube-system"

# Globals for MACs for use in cleanup
TARGET_POD_MAC_GLOBAL=""
SOURCE_POD_ALPHA_MAC_GLOBAL=""
SOURCE_POD_BETA_MAC_GLOBAL=""
DEST_POD_GAMMA_MAC_GLOBAL=""


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

    log_info "  Deleting MultiNetworkPolicy ${MNP_NAMESPACE}/${MNP_NAME}..."
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_FILE}"
    log_info "  Waiting for controller to process MultiNetworkPolicy deletion (15s)..."
    sleep 15

    log_info "  Deleting Pods..."
    ${KUBECTL} delete --ignore-not-found=true -f "${DEST_POD_GAMMA_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${SOURCE_POD_BETA_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${SOURCE_POD_ALPHA_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${TARGET_POD_FILE}"

    log_info "  Waiting for Pods to be deleted (may take a bit)..."
    ${KUBECTL} wait --for=delete pod/"${DEST_POD_GAMMA_NAME}" -n "${DEST_POD_GAMMA_NAMESPACE}" --timeout=180s || log_warn "⚠️ Timeout/Not Found waiting for pod ${DEST_POD_GAMMA_NAME} to be deleted."
    ${KUBECTL} wait --for=delete pod/"${SOURCE_POD_BETA_NAME}" -n "${SOURCE_POD_BETA_NAMESPACE}" --timeout=180s || log_warn "⚠️ Timeout/Not Found waiting for pod ${SOURCE_POD_BETA_NAME} to be deleted."
    ${KUBECTL} wait --for=delete pod/"${SOURCE_POD_ALPHA_NAME}" -n "${SOURCE_POD_ALPHA_NAMESPACE}" --timeout=180s || log_warn "⚠️ Timeout/Not Found waiting for pod ${SOURCE_POD_ALPHA_NAME} to be deleted."
    ${KUBECTL} wait --for=delete pod/"${TARGET_POD_NAME}" -n "${TARGET_POD_NAMESPACE}" --timeout=180s || log_warn "⚠️ Timeout/Not Found waiting for pod ${TARGET_POD_NAME} to be deleted."

    log_info "  Waiting for controller to process Pods deletion (15s)..."
    sleep 15

    log_info "  Deleting Namespaces..."
    ${KUBECTL} delete --ignore-not-found=true -f "${NS_CLIENT_BETA_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NS_CLIENT_ALPHA_FILE}"
    ${KUBECTL} delete --ignore-not-found=true -f "${NS_TARGET_FILE}"
    
    log_info "  Waiting for Namespaces to be deleted (may take a bit)..."
    ${KUBECTL} wait --for=delete namespace/"${DEST_POD_GAMMA_NAMESPACE}" --timeout=180s || log_warn "⚠️ Timeout waiting for ${DEST_POD_GAMMA_NAMESPACE} to be deleted."
    ${KUBECTL} wait --for=delete namespace/"${SOURCE_POD_BETA_NAMESPACE}" --timeout=180s || log_warn "⚠️ Timeout waiting for ${SOURCE_POD_BETA_NAMESPACE} to be deleted."
    ${KUBECTL} wait --for=delete namespace/"${TARGET_POD_NAMESPACE}" --timeout=180s || log_warn "⚠️ Timeout waiting for ${TARGET_POD_NAMESPACE} to be deleted."

    log_info "  Deleting NetworkAttachmentDefinition..."
    ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"
    
    log_info "  Checking if ruleset is clean after cleanup..."
    KIND_CONTROL_PLANE_ID_CLEANUP=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
    if [[ -n "$KIND_CONTROL_PLANE_ID_CLEANUP" ]]; then
        log_info "  Waiting a bit more for reconciler (10s)..."
        sleep 10
        FINAL_RULESET=$(${EXEC_KIND} nft list ruleset bridge)
        
        ORPHANED_INGRESS_CHAIN_PATTERN="KUBE_MULTI_INGRESS_[0-9a-fA-F]{12}" 
        ORPHANED_EGRESS_CHAIN_PATTERN="KUBE_MULTI_EGRESS_[0-9a-fA-F]{12}"   

        ERROR_FOUND_CLEANUP=0
        if echo "$FINAL_RULESET" | grep -qE "${ORPHANED_INGRESS_CHAIN_PATTERN}"; then
            log_error "❌ CLEANUP ERROR: Pod's specific Chain KUBE_MULTI_INGRESS still exist!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -qE "${ORPHANED_EGRESS_CHAIN_PATTERN}"; then
            log_error "❌ CLEANUP ERROR: Pod's specific Chain KUBE_MULTI_EGRESS still exist!"
            ERROR_FOUND_CLEANUP=1
        fi
        if echo "$FINAL_RULESET" | grep -q "set mnp-"; then
            log_error "❌ CLEANUP ERROR: Sets 'mnp-' still exists!"
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

TEST_NAME=$(cat "${SCENARIO_DIR}/test.def")

log_info "🚀 Starting E2E Test: ${TEST_NAME}"

${KUBECTL} apply -f "${NAD_FILE}"
${KUBECTL} apply -f "${NS_TARGET_FILE}"
${KUBECTL} apply -f "${NS_CLIENT_ALPHA_FILE}"
${KUBECTL} apply -f "${NS_CLIENT_BETA_FILE}"
${KUBECTL} apply -f "${TARGET_POD_FILE}"
${KUBECTL} apply -f "${SOURCE_POD_ALPHA_FILE}"
${KUBECTL} apply -f "${SOURCE_POD_BETA_FILE}"
${KUBECTL} apply -f "${DEST_POD_GAMMA_FILE}"

log_info "⏳ Waiting pod ${TARGET_POD_NAMESPACE}/${TARGET_POD_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${TARGET_POD_NAMESPACE}" --timeout=240s
TARGET_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${TARGET_POD_NAMESPACE}")
if [[ -z "$TARGET_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address for pod ${TARGET_POD_NAME} not found. Aborting."
    exit 1
fi

log_info "⏳ Waiting pod ${SOURCE_POD_ALPHA_NAMESPACE}/${SOURCE_POD_ALPHA_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${SOURCE_POD_ALPHA_NAME}" -n "${SOURCE_POD_ALPHA_NAMESPACE}" --timeout=240s
SOURCE_POD_ALPHA_MAC_GLOBAL=$(get_pod_mac "${SOURCE_POD_ALPHA_NAME}" "${SOURCE_POD_ALPHA_NAMESPACE}")
if [[ -z "$SOURCE_POD_ALPHA_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address for pod ${SOURCE_POD_ALPHA_NAME} not found. Aborting."
    exit 1
fi

log_info "⏳ Waiting pod ${SOURCE_POD_BETA_NAMESPACE}/${SOURCE_POD_BETA_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${SOURCE_POD_BETA_NAME}" -n "${SOURCE_POD_BETA_NAMESPACE}" --timeout=240s
SOURCE_POD_BETA_MAC_GLOBAL=$(get_pod_mac "${SOURCE_POD_BETA_NAME}" "${SOURCE_POD_BETA_NAMESPACE}")
if [[ -z "$SOURCE_POD_BETA_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address for pod ${SOURCE_POD_BETA_NAME} not found. Aborting."
    exit 1
fi

log_info "⏳ Waiting pod ${DEST_POD_GAMMA_NAMESPACE}/${DEST_POD_GAMMA_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${DEST_POD_GAMMA_NAME}" -n "${DEST_POD_GAMMA_NAMESPACE}" --timeout=240s
DEST_POD_GAMMA_MAC_GLOBAL=$(get_pod_mac "${DEST_POD_GAMMA_NAME}" "${DEST_POD_GAMMA_NAMESPACE}")
if [[ -z "$DEST_POD_GAMMA_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address for pod ${DEST_POD_GAMMA_NAME} not found. Aborting."
    exit 1
fi

sleep 15s
${KUBECTL} apply -f "${MNP_FILE}"
log_info "⏳ Waiting mnp-nft-bridge controller process the changes (20 seconds)..."
sleep 20

log_info "🔎 Starting nftables checking..."
KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]
then
    log_error "❌ Failed to obtain container ID for Kind's control-plane."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${TARGET_POD_NAMESPACE}" "${TARGET_POD_NAME}")
EXPECTED_INGRESS_CHAIN_NAME="KUBE_MULTI_INGRESS_${EXPECTED_CHAIN_SUFFIX}"
EXPECTED_EGRESS_CHAIN_NAME="KUBE_MULTI_EGRESS_${EXPECTED_CHAIN_SUFFIX}"


# --- Ingress Checks ---
log_info "🔎 Checking INGRESS rules for pod ${TARGET_POD_NAMESPACE}/${TARGET_POD_NAME} (MAC: ${TARGET_POD_MAC_GLOBAL})"

JUMP_RULE_INGRESS_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_CHAIN_NAME}" || echo "")
if [[ -z "$JUMP_RULE_INGRESS_OUTPUT" ]]; then
    log_error "❌ Ingress Jump rule for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_CHAIN_NAME} NOT found."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS; exit 1
fi
log_success "✔️ Ingress Jump rule found. Pod's Ingress Chain: ${EXPECTED_INGRESS_CHAIN_NAME}"

log_info "🔎 Checking PRESENCE of DROP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} in KUBE_MULTI_INGRESS chain..."
DROP_RULE_INGRESS_BASE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} drop" || echo "NOT_FOUND")
if [[ "$DROP_RULE_INGRESS_BASE_OUTPUT" == "NOT_FOUND" ]]; then
    log_error "❌ Specific DROP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} was NOT found in KUBE_MULTI_INGRESS, but should have been."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS; exit 1
else
    log_success "✔️ Specific DROP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} found in KUBE_MULTI_INGRESS, as expected."
fi

log_info "🔎 Checking rules within chain ${EXPECTED_INGRESS_CHAIN_NAME}..."
INGRESS_POD_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_CHAIN_NAME}")

# INGRESS RULE 1: from IPBlock 192.0.2.10/32 to TCP/80 e TCP/metrics (9090)
log_info "🔎  1.1: Checking Ingress Rule 1 (IPBlock 192.0.2.10/32 -> TCP/80, TCP/9090)"
EXPECTED_INGRESS_IP_R1="192.0.2.10"
EXPECTED_INGRESS_TCP_PORT_R1_1="80"
EXPECTED_INGRESS_TCP_PORT_R1_2="9090"

RULE_LINE_R1=$(echo "$INGRESS_POD_CHAIN_RULES" | grep "ip saddr @mnp-src-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)

if [[ -z "$RULE_LINE_R1" ]]
then
    log_error "❌ Ingress Rule 1 (IPBlock -> TCP/Ports) not found."
    echo "$INGRESS_POD_CHAIN_RULES"
    exit 1
fi

SRC_IP_SET_NAME_R1=$(echo "$RULE_LINE_R1" | grep -o 'mnp-src-ip-[a-f0-9]\{16\}' | head -n1)
TCP_PORT_SET_NAME_R1=$(echo "$RULE_LINE_R1" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
if [[ -z "$SRC_IP_SET_NAME_R1" || -z "$TCP_PORT_SET_NAME_R1" ]]
then
    log_error "❌ Failed to extract set names from Ingress Rule 1."
    exit 1
fi

${EXEC_KIND} nft list set bridge filter "${SRC_IP_SET_NAME_R1}" | grep -qF "${EXPECTED_INGRESS_IP_R1}" || \
    { log_error "❌ Set ${SRC_IP_SET_NAME_R1} does not contain ${EXPECTED_INGRESS_IP_R1}"; exit 1; }
${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME_R1}" | grep -qE "(^|[[:space:],{])${EXPECTED_INGRESS_TCP_PORT_R1_1}([[:space:],}]|$)" || \
    { log_error "❌ Set ${TCP_PORT_SET_NAME_R1} does not contain ${EXPECTED_INGRESS_TCP_PORT_R1_1}"; exit 1; }
${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME_R1}" | grep -qE "(^|[[:space:],{])${EXPECTED_INGRESS_TCP_PORT_R1_2}([[:space:],}]|$)" || \
    { log_error "❌ Set ${TCP_PORT_SET_NAME_R1} does not contain ${EXPECTED_INGRESS_TCP_PORT_R1_2}"; exit 1; }
log_success "✔️ Ingress Rule 1 (IPBlock) checked."

# INGRESS RULE 2: from PodSelector (source-pod-alpha MAC) to UDP/dns-udp (53)
log_info "🔎  1.2: Checking Ingress Rule 2 (PodSelector ${SOURCE_POD_ALPHA_MAC_GLOBAL} -> UDP/53)"
EXPECTED_INGRESS_UDP_PORT_R2="53"
RULE_LINE_R2=""
SRC_MAC_SET_NAME_R2=""
UDP_PORT_SET_NAME_R2=""
FILTERED_LINES_R2=$(echo "$INGRESS_POD_CHAIN_RULES" | grep "ether saddr @mnp-src-mac-" | grep "udp dport @mnp-udp-port-" | grep "accept")
while IFS= read -r rule_line_candidate; do
    temp_src_mac_set=$(echo "$rule_line_candidate" | grep -o 'mnp-src-mac-[a-f0-9]\{16\}' | head -n1)
    temp_udp_port_set=$(echo "$rule_line_candidate" | grep -o 'mnp-udp-port-[a-f0-9]\{16\}' | head -n1)
    if [[ -n "$temp_src_mac_set" && -n "$temp_udp_port_set" ]]; then
        if ${EXEC_KIND} nft list set bridge filter "$temp_src_mac_set" | grep -qF "${SOURCE_POD_ALPHA_MAC_GLOBAL}"; then
            if ${EXEC_KIND} nft list set bridge filter "$temp_udp_port_set" | grep -qE "(^|[[:space:],{])${EXPECTED_INGRESS_UDP_PORT_R2}([[:space:],}]|$)"; then
                RULE_LINE_R2="$rule_line_candidate"; SRC_MAC_SET_NAME_R2="$temp_src_mac_set"; UDP_PORT_SET_NAME_R2="$temp_udp_port_set"; break
            fi; fi; fi
done < <(echo "$FILTERED_LINES_R2")

if [[ -z "$RULE_LINE_R2" ]]
then
    log_error "❌ Ingress rule 2 (PodSelector ${SOURCE_POD_ALPHA_MAC_GLOBAL} -> UDP/${EXPECTED_INGRESS_UDP_PORT_R2}) not found."
    echo "$INGRESS_POD_CHAIN_RULES"
    exit 1
fi
log_success "✔️ Ingress 2 (PodSelector) rule checked (MAC Set: ${SRC_MAC_SET_NAME_R2}, UDP Port Set: ${UDP_PORT_SET_NAME_R2})."

# INGRESS RULE 3: from NamespaceSelector (ns-complex-client-alpha, source-pod-beta MAC) to TCP/443
log_info "🔎  1.3: Checking Ingress Rule 3 (NamespaceSelector ${SOURCE_POD_BETA_MAC_GLOBAL} -> TCP/443)"
EXPECTED_INGRESS_TCP_PORT_R3="443"
RULE_LINE_R3=""
SRC_MAC_SET_NAME_R3=""
TCP_PORT_SET_NAME_R3=""
FILTERED_LINES_R3=$(echo "$INGRESS_POD_CHAIN_RULES" | grep "ether saddr @mnp-src-mac-" | grep "tcp dport @mnp-tcp-port-" | grep "accept")
while IFS= read -r rule_line_candidate; do
    temp_src_mac_set=$(echo "$rule_line_candidate" | grep -o 'mnp-src-mac-[a-f0-9]\{16\}' | head -n1)
    temp_tcp_port_set=$(echo "$rule_line_candidate" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
    if [[ -n "$temp_src_mac_set" && -n "$temp_tcp_port_set" ]]; then
        if ${EXEC_KIND} nft list set bridge filter "$temp_src_mac_set" | grep -qF "${SOURCE_POD_BETA_MAC_GLOBAL}"; then
            if ${EXEC_KIND} nft list set bridge filter "$temp_tcp_port_set" | grep -qE "(^|[[:space:],{])${EXPECTED_INGRESS_TCP_PORT_R3}([[:space:],}]|$)"; then
                RULE_LINE_R3="$rule_line_candidate"; SRC_MAC_SET_NAME_R3="$temp_src_mac_set"; TCP_PORT_SET_NAME_R3="$temp_tcp_port_set"; break
            fi; fi; fi
done < <(echo "$FILTERED_LINES_R3")

if [[ -z "$RULE_LINE_R3" ]]
then
    log_error "❌ Ingress rule 3 (NamespaceSelector ${SOURCE_POD_BETA_MAC_GLOBAL} -> TCP/${EXPECTED_INGRESS_TCP_PORT_R3}) not found."
    echo "$INGRESS_POD_CHAIN_RULES"
    exit 1
fi
log_success "✔️ Ingress Rule 3 (NamespaceSelector) checked (MAC Set: ${SRC_MAC_SET_NAME_R3}, TCP Port Set: ${TCP_PORT_SET_NAME_R3})."

# --- Egress Checks ---
log_info "🔎 Checking EGRESS rules for pod ${TARGET_POD_NAMESPACE}/${TARGET_POD_NAME} (MAC: ${TARGET_POD_MAC_GLOBAL})"
JUMP_RULE_EGRESS_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
    grep -F "ether saddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_EGRESS_CHAIN_NAME}" || echo "")
if [[ -z "$JUMP_RULE_EGRESS_OUTPUT" ]]
then
    log_error "❌ JUMP Egress rule for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_EGRESS_CHAIN_NAME} NOT found."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS
    exit 1
fi
log_success "✔️ JUMP Egress rule found. Egress pod chain: ${EXPECTED_EGRESS_CHAIN_NAME}"

log_info "🔎 Checking PRESENCE of DROP Egress rule for MAC ${TARGET_POD_MAC_GLOBAL} in chain KUBE_MULTI_EGRESS..."
DROP_RULE_EGRESS_BASE_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
    grep -F "ether saddr ${TARGET_POD_MAC_GLOBAL} drop" || echo "NOT_FOUND")
if [[ "$DROP_RULE_EGRESS_BASE_OUTPUT" == "NOT_FOUND" ]]
then
    log_error "❌ Specific DROP Egress rule for MAC ${TARGET_POD_MAC_GLOBAL} was NOT found in KUBE_MULTI_EGRESS, but should have been."
    ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS
    exit 1
else
    log_success "✔️ Specific DROP Egress rule for MAC ${TARGET_POD_MAC_GLOBAL} found in KUBE_MULTI_EGRESS, as expected."
fi

log_info "🔎 Checking rules inside chain ${EXPECTED_EGRESS_CHAIN_NAME}..."
EGRESS_POD_CHAIN_RULES=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_EGRESS_CHAIN_NAME}")



# EGRESS RULE 1: to IPBlock 203.0.113.5/32 to TCP/8443
log_info "🔎  2.1: Checking Egress Rule 1 (IPBlock 203.0.113.5/32 -> TCP/8443)"
EXPECTED_EGRESS_IP_R1="203.0.113.5"
EXPECTED_EGRESS_TCP_PORT_R1="8443"
RULE_LINE_E1=$(echo "$EGRESS_POD_CHAIN_RULES" | grep "ip daddr @mnp-dst-ip-" | grep "tcp dport @mnp-tcp-port-" | grep "accept" | head -n1)
if [[ -z "$RULE_LINE_E1" ]]
then
    log_error "❌ Egress Rule 1 (IPBlock -> TCP/8443) not found."
    echo "$EGRESS_POD_CHAIN_RULES"
    exit 1
fi

DST_IP_SET_NAME_E1=$(echo "$RULE_LINE_E1" | grep -o 'mnp-dst-ip-[a-f0-9]\{16\}' | head -n1)
TCP_PORT_SET_NAME_E1=$(echo "$RULE_LINE_E1" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1)
if [[ -z "$DST_IP_SET_NAME_E1" || -z "$TCP_PORT_SET_NAME_E1" ]]
then
    log_error "❌ Failed to extract set names from Egress Rule 1."
    exit 1
fi

${EXEC_KIND} nft list set bridge filter "${DST_IP_SET_NAME_E1}" | grep -qF "${EXPECTED_EGRESS_IP_R1}" || \
    { log_error "❌ Set ${DST_IP_SET_NAME_E1} does not contain ${EXPECTED_EGRESS_IP_R1}"; exit 1; }
${EXEC_KIND} nft list set bridge filter "${TCP_PORT_SET_NAME_E1}" | grep -qE "(^|[[:space:],{])${EXPECTED_EGRESS_TCP_PORT_R1}([[:space:],}]|$)" || \
    { log_error "❌ Set ${TCP_PORT_SET_NAME_E1} does not contain ${EXPECTED_EGRESS_TCP_PORT_R1}"; exit 1; }
log_success "✔️ Egress Rule 1 (IPBlock) checked."

# EGRESS RULE 2: to NamespaceSelector (team: beta, dest-pod-gamma MAC) AND PodSelector (service: external-db) to TCP/5432
log_info "🔎  2.2: Checking Egress Rule 2 (NS+PodSelector ${DEST_POD_GAMMA_MAC_GLOBAL} -> TCP/5432)"
EXPECTED_EGRESS_TCP_PORT_R2="5432"
RULE_LINE_E2=""
DST_MAC_SET_NAME_E2=""
TCP_PORT_SET_NAME_E2=""
# Filters lines that use a destination MAC set and a destination TCP port set
FILTERED_LINES_E2=$(echo "$EGRESS_POD_CHAIN_RULES" | grep "ether daddr @mnp-dst-mac-" | grep "tcp dport @mnp-tcp-port-" | grep "accept")

while IFS= read -r rule_line_candidate; do
    temp_dst_mac_set=$(echo "$rule_line_candidate" | grep -o 'mnp-dst-mac-[a-f0-9]\{16\}' | head -n1 | tr -d '\r\n')
    temp_tcp_port_set=$(echo "$rule_line_candidate" | grep -o 'mnp-tcp-port-[a-f0-9]\{16\}' | head -n1 | tr -d '\r\n')

    if [[ -n "$temp_dst_mac_set" && -n "$temp_tcp_port_set" ]]
    then
        # Check if this target MAC set contains the expected MAC
        set_content_dst_mac_output=$(${EXEC_KIND} nft list set bridge filter "$temp_dst_mac_set" 2>&1)
        set_content_dst_mac_exit_code=$?
        if [[ $set_content_dst_mac_exit_code -ne 0 ]]
        then
            set_content_dst_mac="SET_COMMAND_FAILED"
        else
            set_content_dst_mac="$set_content_dst_mac_output"
        fi
        
        if [[ "$set_content_dst_mac" != "SET_COMMAND_FAILED" ]] && echo "$set_content_dst_mac" | grep -qF "${DEST_POD_GAMMA_MAC_GLOBAL}"
        then
            # Now check if the associated TCP port set contains the expected port
            set_content_tcp_port_output=$(${EXEC_KIND} nft list set bridge filter "$temp_tcp_port_set" 2>&1)
            set_content_tcp_port_exit_code=$?
            if [[ $set_content_tcp_port_exit_code -ne 0 ]]
            then
                set_content_tcp_port="SET_COMMAND_FAILED"
            else
                set_content_tcp_port="$set_content_tcp_port_output"
            fi

            if [[ "$set_content_tcp_port" != "SET_COMMAND_FAILED" ]] && echo "$set_content_tcp_port" | grep -qE "(^|[[:space:],{])${EXPECTED_EGRESS_TCP_PORT_R2}([[:space:],}]|$)"
            then
                DST_MAC_SET_NAME_E2="$temp_dst_mac_set"
                TCP_PORT_SET_NAME_E2="$temp_tcp_port_set"
                RULE_LINE_E2="$rule_line_candidate" 
                break 
            fi
        fi
    fi
done < <(echo "$FILTERED_LINES_E2")

if [[ -z "$RULE_LINE_E2" ]]
then
    log_error "❌ Egress Rule 2 (NS+PodSelector ${DEST_POD_GAMMA_MAC_GLOBAL} -> TCP/${EXPECTED_EGRESS_TCP_PORT_R2}) not found."
    echo "Rules in Egress chain ${EXPECTED_EGRESS_CHAIN_NAME}:"
    echo "$EGRESS_POD_CHAIN_RULES"
    exit 1
fi
log_success "✔️ Egress Rule 2 (NS+PodSelector) checked (MAC Set: ${DST_MAC_SET_NAME_E2}, TCP Port Set: ${TCP_PORT_SET_NAME_E2})."


# 5. NftPodChainMetadataCache contains entry for this chain/pod/policy.
log_info "🔎 5. Checking NftPodChainMetadataCache in controller's log..."
CONTROLLER_POD_NAME=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [[ -z "$CONTROLLER_POD_NAME" ]]; then
    log_warn "⚠️ Not able to find controller pod mnp-nft-bridge. Jumping NftPodChainMetadataCache check."
else
    # Ingress Cache Key
    EXPECTED_CACHE_KEY_INGRESS="${EXPECTED_CHAIN_SUFFIX}_ingress"
    log_info "   Looking for Ingress cache key: ${EXPECTED_CACHE_KEY_INGRESS} with PolicyIngressRuleCount: 3, IsIsolationChain:false"
    
    INGRESS_CACHE_LOGS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=10m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" || echo "")

    INGRESS_COUNT_MATCH=false
    ISOLATION_FLAG_MATCH_INGRESS=false

    if [[ -n "$INGRESS_CACHE_LOGS" ]]; then
        if echo "$INGRESS_CACHE_LOGS" | grep -q "PolicyIngressRuleCount: 3"
        then 
            INGRESS_COUNT_MATCH=true
        fi
        if echo "$INGRESS_CACHE_LOGS" | grep -q "IsIsolationChain:false"
        then
            ISOLATION_FLAG_MATCH_INGRESS=true
        fi
    fi

    if [[ "$INGRESS_COUNT_MATCH" == true && "$ISOLATION_FLAG_MATCH_INGRESS" == true ]]; then
        log_success "✔️ Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} with correct rule count and isolation flag found."
    else
        log_error "❌ Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} with PolicyIngressRuleCount:3 and IsIsolationChain:false NOT found or incorrect."
        log_info "   Logs found for key ${EXPECTED_CACHE_KEY_INGRESS}:"
        echo "$INGRESS_CACHE_LOGS" | tail -n 5
        log_info "   Checked: PolicyIngressRuleCount: 3 (Found: $INGRESS_COUNT_MATCH), IsIsolationChain:false (Found: $ISOLATION_FLAG_MATCH_INGRESS)"
        exit 1
    fi

    # Egress Cache Key
    EXPECTED_CACHE_KEY_EGRESS="${EXPECTED_CHAIN_SUFFIX}_egress"
    log_info "   Looking for Egress cache key: ${EXPECTED_CACHE_KEY_EGRESS} with PolicyEgressRuleCount: 2, IsIsolationChain:false"

    EGRESS_CACHE_LOGS=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=10m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_EGRESS}" || echo "")

    EGRESS_COUNT_MATCH=false
    ISOLATION_FLAG_MATCH_EGRESS=false

    if [[ -n "$EGRESS_CACHE_LOGS" ]]; then
        if echo "$EGRESS_CACHE_LOGS" | grep -q "PolicyEgressRuleCount: 2"
        then
            EGRESS_COUNT_MATCH=true
        fi
        if echo "$EGRESS_CACHE_LOGS" | grep -q "IsIsolationChain:false"
        then
            ISOLATION_FLAG_MATCH_EGRESS=true
        fi
    fi
        
    if [[ "$EGRESS_COUNT_MATCH" == true && "$ISOLATION_FLAG_MATCH_EGRESS" == true ]]; then
        log_success "✔️ Egress entry for ${EXPECTED_CACHE_KEY_EGRESS} with correct rule count and isolation flag found."
    else
        log_error "❌ Egress entry for ${EXPECTED_CACHE_KEY_EGRESS} with PolicyEgressRuleCount:2 and IsIsolationChain:false NOT found or incorrect."
        log_info "   Logs found for key ${EXPECTED_CACHE_KEY_EGRESS}:"
        echo "$EGRESS_CACHE_LOGS" | tail -n 5 
        log_info "   Checked: PolicyEgressRuleCount: 2 (Found: $EGRESS_COUNT_MATCH), IsIsolationChain:false (Found: $ISOLATION_FLAG_MATCH_EGRESS)"
        exit 1
    fi
fi

log_info "✅ Test finished: ${TEST_NAME}"
