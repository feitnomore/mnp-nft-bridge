
# MNP-NFT-Bridge End-to-End (E2E) Tests

This directory contains the end-to-end test suite for the mnp-nft-bridge controller. Each subdirectory in scenarios/ represents a distinct test case designed to verify a specific piece of functionality in a live Kubernetes environment.

  

The tests are designed to be self-contained and idempotent, ensuring that they can be run repeatedly and in any order.

  

Running Tests

Tests are executed via the execute.sh script within each scenario's directory. A master script, scenarios/mass.sh, is available to run all tests in sequence.

  

Each test scenario generally follows these steps:

  

**Setup:** Creates the necessary Kubernetes resources (Namespaces, NADs, Pods, MNPs) to establish a baseline state.

**Action:** Performs the primary action being tested (e.g., updating a Pod's label, deleting a Namespace, restarting the controller).

**Verification:** Inspects the nftables ruleset within the Kind node to assert that the controller has reconciled the cluster state correctly. It also checks the controller's logs for specific cache-related events.

**Cleanup:** Deletes all resources created during the test to ensure a clean state for subsequent runs.

  

## 1. Pod Lifecycle & Labeling

This group tests how the controller reacts to Pod events and label changes.

  

### pod_create_matches_existing_mnp

  

**Purpose:** To verify that when a new Pod is created with labels that match an already existing MultiNetworkPolicy, the controller correctly applies the policy rules to it.

**Setup:** A NetworkAttachmentDefinition (NAD) and a MultiNetworkPolicy (that selects pods with app: foo) are created first.

**Action:** A new Pod with the label app: foo is created.

**Verification:** The script confirms that the controller creates the necessary nftables resources for the new Pod: a jump rule in the main KUBE_MULTI_INGRESS chain pointing to a new, pod-specific chain, and the corresponding sets and rules within that new chain.

  
  

### pod_create_no_matching_mnp

  

**Purpose:** To ensure that creating a Pod with a secondary network interface, but with labels that do not match any MultiNetworkPolicy, results in no nftables rules being created for it.

**Setup:** A NAD and an MNP (that selects app: foo) are created.

**Action:** A new Pod with a different label (app: bar) is created.

**Verification:** The script checks for the absence of any nftables jump rules, pod-specific chains, or drop rules related to the new Pod's MAC address.

  
  

### pod_delete_matching_mnp

  

**Purpose:** To confirm that when a Pod protected by a MultiNetworkPolicy is deleted, the controller correctly cleans up all associated nftables resources.

**Setup:** A NAD, MNP, and a matching Pod are created. The test first verifies that the nftables rules exist.

**Action:** The Pod is deleted.

**Verification:** The script confirms that the pod-specific nftables chain, all associated sets (mnp-*), and the jump rule from the main chain have been completely removed.

  
  

### pod_update_label_matches_mnp

  

**Purpose:** To test the dynamic application of a policy when a running Pod's labels are changed to match a MultiNetworkPolicy.

**Setup:** A NAD, MNP (selecting app: foo), and a Pod with a non-matching label (app: bar) are created. The test verifies that no rules exist initially.

**Action:** The Pod's label is changed from app: bar to app: foo.

**Verification:** The script confirms that the controller detects the label change and creates the full set of nftables rules for the Pod.

  
  

### pod_update_label_no_longer_matches_mnp

  

**Purpose:** To test the dynamic removal of a policy when a running Pod's labels are changed to no longer match a MultiNetworkPolicy.

**Setup:** A NAD, MNP (selecting app: foo), and a Pod with a matching label (app: foo) are created. The test verifies that the rules exist initially.

**Action:** The Pod's label is changed from app: foo to app: bar.

**Verification:** The script confirms that the controller detects the change and removes all nftables resources associated with that Pod and policy.


### pod_restarts_same_mac

  

**Purpose:** To test the controller's resilience when a Pod is deleted and quickly recreated (simulating a restart). This ensures the controller can handle the rapid delete/add events and correctly re-establish the policy.

**Setup:** A NAD, MNP, and a Pod are created, and the initial rules are verified.

**Action:** The Pod is force-deleted and then immediately re-applied from its manifest.

**Verification:** The script confirms that the old rules are cleaned up and then correctly recreated for the new instance of the Pod, using its MAC address (which may or may not be the same as the original).

  

# 2. Namespace Lifecycle & Labeling

This group tests how the controller handles namespaceSelector in policies.

  

### ns_create_matches_mnp_selector

  

**Purpose:** To verify that when a new Namespace is created with labels matching an MNP's namespaceSelector, the controller correctly updates the policy to allow traffic from Pods in that new namespace.

**Setup:** A target Pod and an MNP are created. The MNP allows ingress from any Pod in a namespace with the label env: client. Initially, no such namespace exists.

**Action:** A new Namespace with the label env: client is created, and a "client" Pod is created within it.

**Verification:** The script confirms that the MAC address of the new client Pod is added to the source MAC set (mnp-src-mac-) in the target Pod's nftables rules.


### ns_delete_removes_mnp_match

 
**Purpose:** To ensure that when a source Namespace is deleted, the controller removes the MAC addresses of its Pods from the nftables rules of any policies that were allowing traffic from it.

**Setup:** A full environment is created: a target Pod, a client Pod in a client Namespace, and an MNP on the target Pod that allows traffic from the client Namespace. The initial rules are verified.

**Action:** The client Namespace (which also deletes the client Pod inside it) is deleted.

**Verification:** The script confirms that the client Pod's MAC address is removed from the source MAC set in the target Pod's nftables rules, effectively revoking access.


### ns_update_label_matches_mnp_selector

**Purpose:** To test the dynamic application of a policy when a label is added to an existing Namespace, causing it to match an MNP's namespaceSelector.

**Setup:** All resources are created, but the client Namespace initially lacks the required label (env: client-update). The test verifies that no access is granted initially.

**Action:** The label env: client-update is added to the client Namespace.

**Verification:** The script confirms that the controller detects the label change and adds the client Pod's MAC address to the target Pod's nftables source MAC set.

### ns_update_label_no_longer_matches_mnp_selector

**Purpose:** To test the dynamic removal of a policy when a label is removed from a Namespace, causing it to no longer match an MNP's namespaceSelector.

**Setup:** All resources are created, and the client Namespace has the matching label. The initial rules are verified.

**Action:** The matching label (env: client-label-remove) is removed from the client Namespace.

**Verification:** The script confirms that the controller detects the change and removes the client Pod's MAC address from the target Pod's nftables source MAC set.

  

# 3. MultiNetworkPolicy (MNP) Lifecycle & Behavior

This group of tests focuses on the core functionality of the controller by validating its response to the creation, update, and deletion of MultiNetworkPolicy resources. It covers a wide range of rule configurations and edge cases to ensure policies are translated into the correct nftables rulesets under various conditions.

  

### mnp_create_ingress_ipblock

**Purpose:** To verify that a basic MultiNetworkPolicy with an ingress rule allowing traffic from specific IP sources is correctly translated into nftables rules.

**Setup:** A NetworkAttachmentDefinition (NAD) and a target Pod are created.

**Action:** A MultiNetworkPolicy is created. Its ingress rule contains two ipBlock entries: one for a single IP (/32) and one for a CIDR range (/16). The rule applies to both TCP and UDP ports.

**Verification:** The script confirms that the controller creates a pod-specific chain and that this chain contains the correct accept rules. It specifically checks that a set-based rule is created for the single IP and a mask-based rule is created for the CIDR range, for both specified protocols.

### mnp_create_egress_podselector

**Purpose:** To test the controller's ability to handle an egress rule where the destination is defined by a podSelector.

**Setup:** A NAD, a source Pod (the one the policy applies to), and a destination Pod (the one selected by the policy) are created.

**Action:** A MultiNetworkPolicy is created on the source Pod. Its egress rule contains a podSelector that matches the labels of the destination Pod.

**Verification:** The script confirms that the controller correctly resolves the podSelector to the destination Pod's MAC address and creates an nftables rule allowing traffic from the source Pod to that specific MAC address on the specified port.

### mnp_create_ingress_ns_selector

**Purpose:** To validate an ingress rule where the source of allowed traffic is defined by a namespaceSelector.

**Setup:** A NAD, a target Pod in a "target" namespace, and a client Pod in a "client" namespace are created. The client namespace has a specific label (env: client).

**Action:** A MultiNetworkPolicy is created on the target Pod. Its ingress rule contains a namespaceSelector that matches the label of the client namespace.

**Verification:** The script confirms that the controller identifies all pods in the matching client namespace and adds their MAC addresses to the mnp-src-mac- set used by the target Pod's nftables rules.

### mnp_create_empty_policy_isolation

**Purpose:** To test the default-deny (isolation) behavior when a policy is applied to a Pod but contains no specific ingress or egress rules.

**Setup:** A NAD and a target Pod are created.

**Action:** A MultiNetworkPolicy is created that selects the target Pod. The policy's spec is empty except for the podSelector and policyTypes: [Ingress, Egress].

**Verification:** The script confirms that the controller creates special _ISOLATION_ chains for both ingress and egress. It verifies that these chains contain only a single drop rule, effectively blocking all traffic to and from the Pod's secondary interface.

### mnp_create_complex_multi_rule

**Purpose:** To serve as a comprehensive "kitchen sink" test, validating that a single MNP with multiple, mixed-type ingress and egress rules is rendered correctly.

**Setup:** A full environment with multiple namespaces and pods is created to serve as sources and destinations for the policy rules.

**Action:** A single, complex MultiNetworkPolicy is applied. Its rules include a mix of ipBlock, podSelector, and namespaceSelector for both ingress and egress traffic, targeting different ports and protocols.

**Verification:** The script performs a detailed check of the resulting nftables ruleset. It confirms that all source and destination peers are correctly resolved to their respective IP/MAC sets and that all corresponding accept rules are created correctly within the single ingress and egress chains for the target Pod.

### mnp_update_add_ingress_rule

**Purpose:** To test the controller's ability to dynamically update an existing policy by adding a new ingress rule to it.

**Setup:** An MNP is created with a single ingress rule. The test first verifies that this initial rule is correctly applied.

**Action:** The MNP manifest is updated to include a second ingress rule and is re-applied to the cluster.

**Verification:** The script confirms that the original nftables rules remain and that new rules corresponding to the second ingress rule are correctly added to the existing pod-specific nftables chain.

### mnp_update_modify_ipblock_cidr

**Purpose:** To ensure that modifying an existing ipBlock rule in an MNP correctly updates the corresponding nftables rule.

**Setup:** An MNP is created with an ingress rule allowing traffic from a specific CIDR (10.0.0.0/24). The initial state is verified.

**Action:** The MNP manifest is modified to change the CIDR in the ipBlock to a new value (10.0.1.0/24) and is re-applied.

**Verification:** The script confirms that the nftables rule is updated to match the new CIDR and, crucially, that the rule for the old CIDR has been removed.

### mnp_update_change_podselector

**Purpose:** To test the controller's ability to re-evaluate which Pods are affected by a policy when the MNP's main podSelector is changed.

**Setup:** Two Pods (A and B) are created. An MNP is created that initially selects Pod A. The test verifies that rules are applied only to Pod A.

**Action:** The MNP's podSelector is updated to match Pod B's labels instead of Pod A's.

**Verification:** The script confirms a two-part outcome: 1) All nftables rules related to Pod A are completely removed. 2) A new set of nftables rules is created and applied to Pod B.

### mnp_update_remove_egress_section

**Purpose:** To verify that completely removing the egress section from an MNP's spec results in the cleanup of all associated egress rules, while leaving ingress rules intact.

**Setup:** An MNP with both ingress and egress rules is created and its initial state is verified.

**Action:** The MNP manifest is updated by deleting the entire egress block and is re-applied.

**Verification:** The script confirms that all nftables resources related to the egress policy (the egress-specific chain, sets, and jump rule) are deleted. It also confirms that all ingress-related nftables resources remain unchanged.

### mnp_delete_removes_all_resources

**Purpose:** To test the full cleanup process when a MultiNetworkPolicy is deleted from the cluster.

**Setup:** A NAD, a Pod, and a matching MNP are created. The test first verifies that all the correct nftables chains, sets, and jump rules have been created.

**Action:** The MultiNetworkPolicy resource is deleted.

**Verification:** The script confirms that all nftables resources created for that policy—including the pod-specific chains, all mnp-* sets, and the jump rules in the base chains—are completely removed.

### mnp_empty_podselector_selects_all_in_ns

**Purpose:** To test the edge case where an MNP has an empty podSelector ({}), which should be interpreted as selecting all Pods within the MNP's own namespace.

**Setup:** Two Pods (A and B) are created in the target namespace, and a third Pod (C) is created in a different namespace.

**Action:** An MNP with an empty podSelector is created in the target namespace.

**Verification:** The script confirms that the policy rules are applied to both Pod A and Pod B. It also confirms that no rules are applied to Pod C, proving the selection is correctly scoped to the MNP's namespace.

### mnp_explicit_policytypes_ingress_only

**Purpose:** To test an edge case where the MNP spec contains rules for both ingress and egress, but the policyTypes field explicitly lists only ["Ingress"].

**Setup:** A Pod and an MNP are created. The MNP has both ingress and egress rule blocks defined.

**Action:** The MNP is applied with policyTypes: ["Ingress"].

**Verification:** The script confirms that only the ingress rules are translated into nftables resources. It explicitly checks for the absence of any egress-related chains or rules, proving that the policyTypes field correctly overrides the presence of rules in the spec.

### mnp_invalid_cidr_in_ipblock

**Purpose:** To test the controller's resilience and error handling when an MNP contains malformed or invalid CIDRs in its ipBlock rules.

**Setup:** A Pod is created.

**Action:** An MNP is applied that contains a mix of valid CIDRs and several invalid ones (e.g., 192.168.300.1/24, not-a-cidr).

**Verification:** The script confirms two things: 1) The controller creates nftables rules only for the valid CIDRs and gracefully ignores the invalid ones. 2) The controller logs clear warning messages indicating which CIDRs were invalid and why they were skipped.

### mnp_delete_after_resource_gone

**Purpose:** To test the edge case where a Pod and its Namespace are deleted before the MultiNetworkPolicy that was targeting them.

**Setup:** A full environment (NAD, Namespace, Pod, MNP) is created and the initial rules are verified.

**Action:** The Pod and then its Namespace are deleted, while the MNP is left in the cluster. After a delay, the MNP is also deleted.

**Verification:** The script confirms that the controller correctly cleans up the rules when the Pod is deleted and handles the final MNP deletion without errors, ensuring no orphaned resources are left behind.

  

# 4. NetworkAttachmentDefinition (NAD) Lifecycle

This group of tests validates how the controller reacts to the lifecycle events (creation, update, deletion) of NetworkAttachmentDefinition (NAD) resources, especially when those NADs are referenced by active MultiNetworkPolicy resources.

### nad_create_activates_mnp

**Purpose:** To verify that an existing MultiNetworkPolicy is correctly activated and applied only after the NetworkAttachmentDefinition it references is created.

**Setup:** A Pod and a MultiNetworkPolicy are created first. The MNP's k8s.v1.cni.cncf.io/policy-for annotation points to a NAD that does not yet exist. The test verifies that no nftables rules are initially created for the Pod.

**Action:** The NetworkAttachmentDefinition (e2e-test-bridge) referenced by the MNP is created.

**Verification:** The script confirms that the controller detects the creation of the NAD, triggers a reconciliation for the waiting MNP, and correctly applies the full set of nftables rules to the target Pod.

### nad_delete_referenced

**Purpose:** To test the controller's behavior when a NetworkAttachmentDefinition that is actively referenced by a MultiNetworkPolicy is deleted.

**Setup:** A complete environment is created: a NAD, a Pod using that NAD, and an MNP targeting the Pod via the NAD. The test first verifies that all nftables rules have been correctly applied.

**Action:** The NetworkAttachmentDefinition resource is deleted from the cluster.

**Verification:** The script confirms that the existing nftables rules for the running Pod remain unchanged. This demonstrates that deleting a NAD does not retroactively remove policies from Pods that are already configured and running on that network.

### nad_update_config_no_type_change

**Purpose:** To ensure that updating a NetworkAttachmentDefinition's configuration in a way that does not change its CNI type (e.g., adding an IPAM section or changing a bridge name) does not cause an unnecessary or incorrect reconciliation of nftables rules.

**Setup:** A NAD, a Pod, and an MNP are created, and the initial nftables rules are verified.

**Action:** The NAD is updated by applying a new manifest with a modified config JSON string. The type field within the config remains "bridge".

**Verification:** The script confirms that the controller correctly identifies that the driver type has not changed and, therefore, makes no changes to the existing nftables rules. The original rules for the Pod remain fully intact.

  

# 5. Controller & Reconciliation Logic

This group of tests validates the core resilience, correctness, and advanced logic of the controller. It focuses on how the controller handles system-level events like restarts, conflicting or overlapping policies, and manual state changes, ensuring the nftables ruleset remains consistent with the desired state defined in the Kubernetes resources.

### controller_restart_reconciles_state

**Purpose:** To test the controller's resilience and ability to reconcile the cluster state after a crash or restart.

**Setup:** A complete set of resources (NAD, Pod, MNP) is created, and the test verifies that the corresponding nftables rules are correctly applied.

**Action:** The controller's own Pod is force-deleted from the kube-system namespace, simulating a restart. The test then waits for the DaemonSet to recreate the Pod and for it to become ready.

**Verification:** The script confirms that after the new controller Pod starts, it correctly re-evaluates the existing Kubernetes resources and ensures the nftables ruleset remains correct and consistent, without creating duplicate rules or removing valid ones.

### controller_reconcile_orphan_cleanup

**Purpose:** To test the controller's self-healing capability by verifying that its periodic reconciliation can detect and correct manual, out-of-band changes made directly to the nftables ruleset.

**Setup:** A Pod and a matching MNP are created, and the initial nftables rules are verified.

**Action:** The script uses nft flush chain to manually delete all the rules inside the pod-specific nftables chain, creating an "orphaned" but empty chain that is inconsistent with the MNP's definition.

**Verification:** After waiting for the controller's reconciliation period, the script confirms that the controller has detected the discrepancy and automatically restored the correct accept rules inside the flushed chain, bringing the system back to the desired state.

### controller_multiple_mnps_same_pod

**Purpose:** To validate how the controller handles a complex scenario where two different MultiNetworkPolicy resources select the same Pod.

**Setup:** A single target Pod is created.

**Action:** Two distinct MultiNetworkPolicy resources (Alpha and Beta) are created. Both policies use a podSelector that matches the target Pod, but each policy defines different ingress rules (e.g., allowing traffic from different IPs on different ports).

**Verification:** The script confirms that the controller creates two separate pod-specific nftables chains for the single Pod—one for Policy Alpha and one for Policy Beta. It verifies that the main KUBE_MULTI_INGRESS chain has two distinct jump rules (one for each policy chain) and that each pod-specific chain contains the correct rules corresponding to its parent MNP.

### controller_pod_multiple_interfaces_one_managed

**Purpose:** To ensure the controller correctly targets only the network interface specified in the MNP's k8s.v1.cni.cncf.io/policy-for annotation when a Pod has multiple secondary network interfaces.

**Setup:** A Pod is created with two secondary network interfaces, attached via two different NADs (one bridge type, one macvlan type).

**Action:** A MultiNetworkPolicy is created that selects the Pod, but its policy-for annotation explicitly references only the bridge NAD.

**Verification:** The script confirms that nftables rules are created only for the MAC address of the Pod's bridge interface. It explicitly checks for the absence of any jump rules or chains related to the MAC address of the macvlan interface, proving the controller correctly ignores unmanaged networks.