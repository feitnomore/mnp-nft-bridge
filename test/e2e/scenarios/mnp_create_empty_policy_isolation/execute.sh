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
POD_FILE="${SCENARIO_DIR}/01_isolated_pod.yaml"
MNP_FILE="${SCENARIO_DIR}/02_mnp_empty_rules.yaml"

TARGET_POD_NAME="isolated-pod-test"
TARGET_POD_NAMESPACE="default"
MNP_NAME="isolate-pod-by-default"
MNP_NAMESPACE="default"

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
    ${KUBECTL} delete --ignore-not-found=true -f "${MNP_FILE}"
    log_info "  Wainting for controller to process MultiNetworkPolicy deletion (15s)..."
    sleep 15

   ${KUBECTL} delete --ignore-not-found=true -f "${POD_FILE}"
    log_info "  Wainting for controller to process Pod deletion (15s)..."
    sleep 15

   ${KUBECTL} delete --ignore-not-found=true -f "${NAD_FILE}"
    
    log_info "  Checking if ruleset is empty after cleanup..."
    KIND_CONTROL_PLANE_ID_CLEANUP=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
    if [[ -n "$KIND_CONTROL_PLANE_ID_CLEANUP" ]]; then
        log_info "  Waiting for reconciler (10s)..."
        sleep 10
        FINAL_RULESET=$(${EXEC_KIND} nft list ruleset bridge)
        
        ORPHANED_ISOLATION_INGRESS_CHAIN_PATTERN="KUBE_MULTI_INGRESS_ISOLATION_"
        ORPHANED_ISOLATION_EGRESS_CHAIN_PATTERN="KUBE_MULTI_EGRESS_ISOLATION_"
        ORPHANED_RULES_INGRESS_CHAIN_PATTERN="KUBE_MULTI_INGRESS_[0-9a-fA-F]{12}" 
        ORPHANED_RULES_EGRESS_CHAIN_PATTERN="KUBE_MULTI_EGRESS_[0-9a-fA-F]{12}"   

        ERROR_FOUND=0
        if echo "$FINAL_RULESET" | grep -qE "${ORPHANED_ISOLATION_INGRESS_CHAIN_PATTERN}"; then
            log_error "❌ CLEANUP ERROR: The Pod's specific KUBE_MULTI_INGRESS_ISOLATION chain may still exist!"
            ERROR_FOUND=1
        fi
        if echo "$FINAL_RULESET" | grep -qE "${ORPHANED_ISOLATION_EGRESS_CHAIN_PATTERN}"; then
            log_error "❌ CLEANUP ERROR: The Pod's specific KUBE_MULTI_EGRESS_ISOLATION chain may still exist!"
            ERROR_FOUND=1
        fi
        if echo "$FINAL_RULESET" | grep -E "${ORPHANED_RULES_INGRESS_CHAIN_PATTERN}" | grep -v "_ISOLATION_" | grep -q .; then
            log_error "❌ CLEANUP ERROR: The Pod's specific KUBE_MULTI_INGRESS (of rules) chain may still exist!"
            ERROR_FOUND=1
        fi
        if echo "$FINAL_RULESET" | grep -E "${ORPHANED_RULES_EGRESS_CHAIN_PATTERN}" | grep -v "_ISOLATION_" | grep -q .; then
            log_error "❌ CLEANUP ERROR: The Pod's specific KUBE_MULTI_EGRESS (of rules) chain may still exist!"
            ERROR_FOUND=1
        fi

        if [[ -n "$TARGET_POD_MAC_GLOBAL" ]]; then
            if echo "$FINAL_RULESET" | grep -q "ether daddr ${TARGET_POD_MAC_GLOBAL} jump"; then
                 log_error "❌ CLEANUP ERROR: JUMP Ingress rule for MAC ${TARGET_POD_MAC_GLOBAL} still exists!"
                 ERROR_FOUND=1
            fi
            if echo "$FINAL_RULESET" | grep -q "ether saddr ${TARGET_POD_MAC_GLOBAL} jump"; then
                 log_error "❌ CLEANUP ERROR: JUMP Egress rule for MAC ${TARGET_POD_MAC_GLOBAL} still exists!"
                 ERROR_FOUND=1
            fi
        fi
        
        if [[ "$ERROR_FOUND" -eq 1 ]]; then
            echo "--- Final Ruleset ---"
            echo "$FINAL_RULESET"
            echo "---------------------"
            # exit 1 
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
${KUBECTL} apply -f "${POD_FILE}"
log_info "⏳ Waiting pod ${TARGET_POD_NAMESPACE}/${TARGET_POD_NAME} to be ready..."
${KUBECTL} wait --for=condition=Ready pod/"${TARGET_POD_NAME}" -n "${TARGET_POD_NAMESPACE}" --timeout=180s
TARGET_POD_MAC_GLOBAL=$(get_pod_mac "${TARGET_POD_NAME}" "${TARGET_POD_NAMESPACE}")
if [[ -z "$TARGET_POD_MAC_GLOBAL" ]]
then
    log_error "❌ MAC Address for pod ${TARGET_POD_NAME} not found. Aborting."
    exit 1
fi

sleep 15s
${KUBECTL} apply -f "${MNP_FILE}"
log_info "⏳ Waiting mnp-nft-bridge controller process the changes (20 seconds)..."
sleep 20

log_info "🔎 Starting nftables checking..."
KIND_CONTROL_PLANE_ID=$("${HACK_DIR}/kind-common.sh" && echo "$KIND_ID")
if [[ -z "$KIND_CONTROL_PLANE_ID" ]]; then
    log_error "❌ Failed to obtain container ID for Kind's control-plane."
    exit 1
fi

EXPECTED_CHAIN_SUFFIX=$(generate_pod_chain_suffix "${MNP_NAME}" "${MNP_NAMESPACE}" "${TARGET_POD_NAMESPACE}" "${TARGET_POD_NAME}")
EXPECTED_INGRESS_ISOLATION_CHAIN_NAME="KUBE_MULTI_INGRESS_ISOLATION_${EXPECTED_CHAIN_SUFFIX}"
EXPECTED_EGRESS_ISOLATION_CHAIN_NAME="KUBE_MULTI_EGRESS_ISOLATION_${EXPECTED_CHAIN_SUFFIX}"

log_info "🔎 1a. Checking if ISOLATION Ingress chain (${EXPECTED_INGRESS_ISOLATION_CHAIN_NAME}) EXISTS..."
if ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_ISOLATION_CHAIN_NAME}" > /dev/null 2>&1; then
    log_success "✔️ ISOLATION Ingress chain ${EXPECTED_INGRESS_ISOLATION_CHAIN_NAME} found."
else
    log_error "❌ ISOLATION Ingress chain ${EXPECTED_INGRESS_ISOLATION_CHAIN_NAME} NOT found."
   ${EXEC_KIND} nft list ruleset bridge; exit 1
fi

log_info "🔎 1b.  Checking if ISOLATION Egress chain (${EXPECTED_EGRESS_ISOLATION_CHAIN_NAME}) EXISTS..."
if ${EXEC_KIND} nft list chain bridge filter "${EXPECTED_EGRESS_ISOLATION_CHAIN_NAME}" > /dev/null 2>&1; then
    log_success "✔️ ISOLATION Egress  ${EXPECTED_EGRESS_ISOLATION_CHAIN_NAME} found."
else
    log_error "❌ ISOLATION Egress chain ${EXPECTED_EGRESS_ISOLATION_CHAIN_NAME} NOT found."
   ${EXEC_KIND} nft list ruleset bridge; exit 1
fi

log_info "🔎 2a. Checking the contents of the ISOLATION Ingress chain ${EXPECTED_INGRESS_ISOLATION_CHAIN_NAME}..."
INGRESS_ISO_RULES_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_INGRESS_ISOLATION_CHAIN_NAME}")
# Extract only the lines BETWEEN the keys of the specific chain definition, remove spaces and empty lines
INGRESS_ISO_ACTUAL_RULES=$(echo "$INGRESS_ISO_RULES_OUTPUT" | \
    sed -n "/chain ${EXPECTED_INGRESS_ISOLATION_CHAIN_NAME} {/,/}/ { /chain ${EXPECTED_INGRESS_ISOLATION_CHAIN_NAME} {/d; /}/d; p; }" | \
    sed 's/^[ \t]*//;s/[ \t]*$//' | grep -vE "^\s*$") # Remove lines that are empty after sed

if [[ "$INGRESS_ISO_ACTUAL_RULES" == "drop" ]]; then
    log_success "✔️ Chain ${EXPECTED_INGRESS_ISOLATION_CHAIN_NAME} contains a single 'drop' rule."
else
    NUM_ACTUAL_RULE_LINES_INGRESS=0
    if [[ -n "$INGRESS_ISO_ACTUAL_RULES" ]]; then
        NUM_ACTUAL_RULE_LINES_INGRESS=$(echo "$INGRESS_ISO_ACTUAL_RULES" | wc -l)
    fi
    log_error "❌ Chain ${EXPECTED_INGRESS_ISOLATION_CHAIN_NAME} DOES NOT contain a single DROP rule. Expected: 'drop'."
    log_info "   Lines extracted (${NUM_ACTUAL_RULE_LINES_INGRESS}):"
    echo -e ">${INGRESS_ISO_ACTUAL_RULES}<"
    log_info "   Chain output:"
    echo "$INGRESS_ISO_RULES_OUTPUT"
    exit 1
fi

log_info "🔎 2b. Checking the contents of the ISOLATION Egress chain ${EXPECTED_EGRESS_ISOLATION_CHAIN_NAME}..."
EGRESS_ISO_RULES_OUTPUT=$(${EXEC_KIND} nft list chain bridge filter "${EXPECTED_EGRESS_ISOLATION_CHAIN_NAME}")
EGRESS_ISO_ACTUAL_RULES=$(echo "$EGRESS_ISO_RULES_OUTPUT" | \
    sed -n "/chain ${EXPECTED_EGRESS_ISOLATION_CHAIN_NAME} {/,/}/ { /chain ${EXPECTED_EGRESS_ISOLATION_CHAIN_NAME} {/d; /}/d; p; }" | \
    sed 's/^[ \t]*//;s/[ \t]*$//' | grep -vE "^\s*$")

if [[ "$EGRESS_ISO_ACTUAL_RULES" == "drop" ]]; then
    log_success "✔️ Chain ${EXPECTED_EGRESS_ISOLATION_CHAIN_NAME} contains a single 'drop' rule."
else
    NUM_ACTUAL_RULE_LINES_EGRESS=0
    if [[ -n "$EGRESS_ISO_ACTUAL_RULES" ]]; then
        NUM_ACTUAL_RULE_LINES_EGRESS=$(echo "$EGRESS_ISO_ACTUAL_RULES" | wc -l)
    fi
    log_error "❌ Chain ${EXPECTED_EGRESS_ISOLATION_CHAIN_NAME} DOES NOT contain a single DROP rule. Expected: 'drop'."
    log_info "  Lines extracted (${NUM_ACTUAL_RULE_LINES_EGRESS}):"
    echo -e ">${EGRESS_ISO_ACTUAL_RULES}<"
    log_info "   Chain output:"
    echo "$EGRESS_ISO_RULES_OUTPUT"
    exit 1
fi

log_info "🔎 3a. Checking JUMP rule in KUBE_MULTI_INGRESS for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_INGRESS_ISOLATION_CHAIN_NAME}..."
JUMP_RULE_INGRESS=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_INGRESS_ISOLATION_CHAIN_NAME}" || echo "")
if [[ -n "$JUMP_RULE_INGRESS" ]]; then
    log_success "✔️ Ingress Jump rule for ${EXPECTED_INGRESS_ISOLATION_CHAIN_NAME} found."
else
    log_error "❌ Ingress Jump rule for ${EXPECTED_INGRESS_ISOLATION_CHAIN_NAME} NOT found."
   ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS; exit 1
fi

log_info "🔎 3b. Checking JUMP rule in KUBE_MULTI_EGRESS for MAC ${TARGET_POD_MAC_GLOBAL} for ${EXPECTED_EGRESS_ISOLATION_CHAIN_NAME}..."
JUMP_RULE_EGRESS=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
    grep -F "ether saddr ${TARGET_POD_MAC_GLOBAL} jump ${EXPECTED_EGRESS_ISOLATION_CHAIN_NAME}" || echo "")
if [[ -n "$JUMP_RULE_EGRESS" ]]; then
    log_success "✔️ Egress Jump rule for ${EXPECTED_EGRESS_ISOLATION_CHAIN_NAME} found."
else
    log_error "❌ Egress Jump rule for ${EXPECTED_EGRESS_ISOLATION_CHAIN_NAME} NOT found."
   ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS; exit 1
fi

log_info "🔎 4a. Checking for PRESENCE of specific DROP rule in KUBE_MULTI_INGRESS for MAC ${TARGET_POD_MAC_GLOBAL}..."
DROP_RULE_INGRESS_BASE=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS | \
    grep -F "ether daddr ${TARGET_POD_MAC_GLOBAL} drop" || echo "")
if [[ -z "$DROP_RULE_INGRESS_BASE" ]]; then
    log_error "❌ Specific DROP rule for MAC ${TARGET_POD_MAC_GLOBAL} NOT found in KUBE_MULTI_INGRESS, but should."
   ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_INGRESS; exit 1
else
    log_success "✔️ Specific DROP rule for MAC ${TARGET_POD_MAC_GLOBAL} found in KUBE_MULTI_INGRESS, as expected: ${DROP_RULE_INGRESS_BASE}"
fi

log_info "🔎 4b. Checking for PRESENCE of specific DROP rule in KUBE_MULTI_EGRESS for MAC ${TARGET_POD_MAC_GLOBAL}..."
DROP_RULE_EGRESS_BASE=$(${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS | \
    grep -F "ether saddr ${TARGET_POD_MAC_GLOBAL} drop" || echo "")
if [[ -z "$DROP_RULE_EGRESS_BASE" ]]; then
    log_error "❌ Specific DROP rule for MAC ${TARGET_POD_MAC_GLOBAL} NOT found in KUBE_MULTI_EGRESS, but should."
   ${EXEC_KIND} nft list chain bridge filter KUBE_MULTI_EGRESS; exit 1
else
    log_success "✔️ Specific DROP rule for MAC ${TARGET_POD_MAC_GLOBAL} found in KUBE_MULTI_EGRESS, as expected: ${DROP_RULE_EGRESS_BASE}"
fi

# 5. NftPodChainMetadataCache contains entry for this chain/pod/policy.
log_info "🔎 5. Checking NftPodChainMetadataCache in controller's log..."
CONTROLLER_POD_NAME=$(${KUBECTL} get pods -n "${NFT_CONTROLLER_NAMESPACE}" -l "${NFT_CONTROLLER_POD_LABEL}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [[ -z "$CONTROLLER_POD_NAME" ]]; then
    log_warn "⚠️ Not able to find controller pod mnp-nft-bridge. Jumping NftPodChainMetadataCache check."
else
    EXPECTED_CACHE_KEY_INGRESS="${EXPECTED_CHAIN_SUFFIX}_ingress"
    EXPECTED_CACHE_KEY_EGRESS="${EXPECTED_CHAIN_SUFFIX}_egress"

    log_info "   Looking for Ingress Cache Key: ${EXPECTED_CACHE_KEY_INGRESS} with IsIsolationChain:true"
    CACHE_LOG_INGRESS_FOUND=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" | grep "IsIsolationChain:true" || echo "")
    if [[ -n "$CACHE_LOG_INGRESS_FOUND" ]]; then
        log_success "✔️ Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} with IsIsolationChain:true found."
    else
        log_error "❌ Ingress entry for ${EXPECTED_CACHE_KEY_INGRESS} with IsIsolationChain:true NOT found."
       ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_INGRESS}" || echo " (no log for this key)"
        exit 1
    fi

    log_info "   Looking for Egress Cache Key: ${EXPECTED_CACHE_KEY_EGRESS} with IsIsolationChain:true"
    CACHE_LOG_EGRESS_FOUND=$(${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | \
        grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_EGRESS}" | grep "IsIsolationChain:true" || echo "")
    if [[ -n "$CACHE_LOG_EGRESS_FOUND" ]]; then
        log_success "✔️ Egress entry for ${EXPECTED_CACHE_KEY_EGRESS} with IsIsolationChain:true found."
    else
        log_error "❌ Egress entry for ${EXPECTED_CACHE_KEY_EGRESS} with IsIsolationChain:true NOT found."
       ${KUBECTL} logs "pod/${CONTROLLER_POD_NAME}" -n "${NFT_CONTROLLER_NAMESPACE}" --since=5m | grep "nftPodChainMetadataCache" | grep "for key: ${EXPECTED_CACHE_KEY_EGRESS}" || echo " (no log for this key)"
        exit 1
    fi
fi

log_info "✅ Test finished: ${TEST_NAME}"
