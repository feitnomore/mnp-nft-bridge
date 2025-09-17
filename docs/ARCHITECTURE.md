# mnp-nft-bridge: A Kubernetes MultiNetworkPolicy Controller for nftables

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/feitnomore/mnp-nft-bridge)](https://goreportcard.com/report/github.com/feitnomore/mnp-nft-bridge)
[![Go.Dev Reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/feitnomore/mnp-nft-bridge)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![Code Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen)](#)
[![GitHub release](https://img.shields.io/github/v/release/feitnomore/mnp-nft-bridge)](https://github.com/feitnomore/mnp-nft-bridge/releases)

```text
                                     __ _          _          _     _
                                    / _| |        | |        (_)   | |
  _ __ ___  _ __  _ __ ______ _ __ | |_| |_ ______| |__  _ __ _  __| | __ _  ___
 | '_ ` _ \| '_ \| '_ \______| '_ \|  _| __|______| '_ \| '__| |/ _` |/ _` |/ _ \
 | | | | | | | | | |_) |     | | | | | | |_       | |_) | |  | | (_| | (_| |  __/
 |_| |_| |_|_| |_| .__/      |_| |_|_|  \__|      |_.__/|_|  |_|\__,_|\__, |\___|
                 | |                                                   __/ |
                 |_|                                                  |___/
```

## Architecture

The mnp-nft-bridge runs as a `DaemonSet` on each node in the Kubernetes cluster. Its core logic is built around the Kubernetes controller pattern.

1.  **Controllers & Informers:** The main process initializes several controllers that watch for changes to key Kubernetes resources. Informers provide an efficient, cache-based mechanism to react to these events.
    -   `MultiNetworkPolicyController`: Watches for MNP creation, updates, and deletions.
    -   `PodController`: Watches for pods, paying close attention to their labels and network status annotations.
    -   `NamespaceController`: Watches for namespace label changes, which can affect `namespaceSelector` rules in policies.
    -   `NetworkAttachmentDefinitionController`: Watches for network definitions to identify which networks are of the `bridge` type and thus managed by this controller.

2.  **Reconciliation Loop:** Events from the informers trigger a central reconciliation loop. This loop is debounced to batch multiple quick changes into a single run. A periodic reconciliation also runs to ensure the state is consistent.

3.  **`nftables` Interaction:**
    *   The desired state is translated into a series of `nftables` operations (add/delete chains, sets, and rules).
    *   These operations are queued and then flushed to the kernel in an atomic batch transaction.
    *   The controller creates a `filter` table in the `bridge` family and establishes base `KUBE_MULTI_INGRESS` and `KUBE_MULTI_EGRESS` chains.
    *   For each pod selected by a policy, a dedicated chain is created. Traffic is directed to these pod-specific chains via `JUMP` rules in the base chains, matched by the pod's MAC address.
    *   A `DROP` rule is placed after the `JUMP` rule for each managed pod, ensuring a \"default deny\" posture for any traffic not explicitly allowed by the policy.

```mermaid
graph TD
    subgraph "Kubernetes Control Plane"
        K8s_API[Kubernetes API Server] -- Stores in --> ETCD[(etcd)]
    end

    subgraph "Worker Node"
        subgraph "mnp-nft-bridge Pod"
            C[Controller Manager]
            C -- Watches --> K8s_API
            
            subgraph "Informers & Caches"
                direction LR
                I_MNP[MultiNetworkPolicy Informer]
                I_Pod[Pod Informer]
                I_NS[Namespace Informer]
                I_NAD[NetworkAttachmentDefinition Informer]
            end

            C -- Events --> R[Reconciliation Loop]
            R -- Reads from --> I_MNP
            R -- Reads from --> I_Pod
            R -- Reads from --> I_NS
            R -- Reads from --> I_NAD
            
            R -- Builds desired state --> Q[Operation Queue]
            Q -- Flushes batch --> NftConn[nftables Connection]
        end

        NftConn -- Manages --> Kernel[Linux Kernel]
        
        subgraph "Kernel Space"
            direction LR
            Kernel -- Contains --> Nftables[nftables Framework]
        end
        
        subgraph "nftables Ruleset"
            style Nftables fill:#f9f,stroke:#333,stroke-width:2px
            direction TB
            BaseChains[Base Chains<br>KUBE_MULTI_INGRESS<br>KUBE_MULTI_EGRESS]
            PodChains[Pod-Specific Chains<br>KUBE_MULTI_..._HASH]
            Sets[Sets<br>mnp-src-ip-..., etc.]
            
            BaseChains -- JUMP --> PodChains
            PodChains -- Uses --> Sets
        end
        
        Nftables -- Contains --> BaseChains
    end

    classDef k8s fill:#326ce5,stroke:#fff,stroke-width:1px,color:#fff;
    classDef controller fill:#e3b341,stroke:#333,stroke-width:1px,color:#000;
    classDef kernel fill:#99cc99,stroke:#333,stroke-width:1px,color:#000;
    
    class A,K8s_API,ETCD k8s;
    class C,I_MNP,I_Pod,I_NS,I_NAD,R,Q,NftConn controller;
    class Kernel,Nftables,BaseChains,PodChains,Sets kernel;
```

### Intra-Node Traffic
For any two pods running on the **same node** and attached to the same secondary bridge network, policies are always enforced correctly.
  
### Inter-Node Traffic (Across Different Nodes)  
Policy enforcement for traffic between pods on **different nodes** depends on your underlying node network topology. mnp-nft-bridge operates at Layer 2, inspecting the source and destination MAC addresses of traffic passing through the CNI bridge.

For inter-node policies to work, the CNI bridges (br0 in the examples) on all relevant nodes must be part of the **same Layer 2 broadcast domain**. This is typically achieved by:

1. Creating a Linux bridge on each node.
2. Attaching a dedicated physical network interface (e.g., eth1) from each node to its local bridge.
3. Connecting these physical interfaces to the same switch or VLAN.  
  
In this configuration, pod-to-pod traffic between nodes is forwarded at Layer 2, preserving the original source pod's MAC address, which allows mnp-nft-bridge to enforce the policy correctly on the destination node.

**Important:** If your nodes are using a standard routed network model (where traffic between nodes is forwarded at Layer 3), the source MAC address of inter-node packets will be rewritten to the source node's MAC address. In this common scenario, mnp-nft-bridge will not be able to enforce policies for pod-to-pod traffic that crosses node boundaries.

