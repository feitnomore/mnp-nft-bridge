# mnp-nft-bridge: A Kubernetes MultiNetworkPolicy Controller for nftables

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/kubevirt-manager/mnp-nft-bridge)](https://goreportcard.com/report/github.com/kubevirt-manager/mnp-nft-bridge)
[![Go.Dev Reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/kubevirt-manager/mnp-nft-bridge)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![Code Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen)](#)
[![GitHub release](https://img.shields.io/github/v/release/kubevirt-manager/mnp-nft-bridge)](https://github.com/kubevirt-manager/mnp-nft-bridge/releases)

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

## Overview

**mnp-nft-bridge** is a specialized Kubernetes controller that acts as a bridge between the `MultiNetworkPolicy` API and the Linux kernel's `nftables` framework. It is designed for environments that use secondary container networks (via Multus CNI) and require fine-grained traffic control at the Layer 2 (MAC address) and Layer 3 (IP address) levels.

The standard Kubernetes `NetworkPolicy` resource is designed for the primary pod network and typically operates at Layer 3/4. However, in complex networking scenarios, such as those in Telco or high-performance computing, pods may have multiple network interfaces. The `MultiNetworkPolicy` CRD addresses this by allowing policy enforcement on these secondary networks.

This controller watches for `MultiNetworkPolicy`, `Pod`, `Namespace`, and `NetworkAttachmentDefinition` resources and dynamically translates the policy rules into an efficient `nftables` ruleset on each node, enforcing the desired traffic flow for secondary networks managed by a `bridge` CNI plugin.

## The Problem It Solves

-   **Enforcement for Secondary Networks:** Standard network policy engines often ignore secondary interfaces attached via Multus.
-   **Layer 2 Filtering:** Provides the ability to filter traffic based on MAC addresses, which is crucial for `bridge` CNI-based networks where pods share the same L2 domain.
-   **Performance:** Leverages `nftables`, the modern and more performant successor to `iptables`, for firewalling.
-   **Dynamic Configuration:** Automatically updates the firewall ruleset in response to changes in the Kubernetes cluster (e.g., pod creation/deletion, policy updates, label changes) without requiring manual intervention.

## Getting Started

This guide explains how to deploy the mnp-nft-bridge controller in your cluster.

### Prerequisites

-   A running Kubernetes cluster.
-   `kubectl` configured to communicate with your cluster.
-   **Multus CNI** must be installed and configured in your cluster.
-   The **`MultiNetworkPolicy` CRD** must be installed. You can install it from the [official repository](https://github.com/k8snetworkplumbingwg/multi-networkpolicy).
-   Each node where the controller will run must have the required `nftables` kernel modules loaded. You can check this with `lsmod | grep nft`. Required modules include: `nf_tables`, `nft_meta_bridge`, `nft_ct`, and `bridge`.

### Deployment

Deploy the mnp-nft-bridge controller as a `DaemonSet` using the provided manifest:

```bash
kubectl apply -f https://github.com/kubevirt-manager/mnp-nft-bridge/releases/download/v0.1.0/deploy-v0.1.0.yaml
```

After applying, the controller will be deployed to the `kube-system` namespace and will begin watching for resources across the cluster.

### Verify the Deployment

Check that the controller pods are running successfully on your nodes:

```bash
kubectl get pods -n kube-system -l app=mnp-nft-bridge
```

You are now ready to create `NetworkAttachmentDefinition`s with a `bridge` type and apply `MultiNetworkPolicy` resources to your pods.

## Documentation

You can find detailed documents under [docs](docs/).

## License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.
