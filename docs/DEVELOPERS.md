# mnp-nft-bridge: A Kubernetes MultiNetworkPolicy Controller for nftables

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/feitnomore/mnp-nft-bridge)](https://goreportcard.com/report/github.com/kubevirt-manager/mnp-nft-bridge)
[![Go.Dev Reference](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/kubevirt-manager/mnp-nft-bridge)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![Code Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen)](#)
[![GitHub release](https://img.shields.io/github/v/release/feitnomore/mnp-nft-bridge)](https://github.com/kubevirt-manager/mnp-nft-bridge/releases)

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

## For Developers

This section provides instructions for setting up a local development environment, building the controller, and running tests.

### Development Environment Setup

The project includes a comprehensive set of scripts to set up a local `kind` cluster with all necessary dependencies.

#### 1. Install Tools

This script downloads `kind`, `kubectl`, Go, and other required utilities into a local `.work/` directory. It does not affect your system-wide installations.

```bash
./hack/get-kind.sh
```

#### 2. Start the Cluster

This script creates a `kind` cluster, disables the default CNI, and installs Cilium (as the primary CNI), Multus, and the `MultiNetworkPolicy` CRDs. It also customizes the cluster nodes with the necessary `nftables` modules and bridge interfaces for testing.

```bash
./hack/cluster-up.sh
```

Your `kind` cluster is now ready for development and testing. The `kubeconfig` is located at `.work/kubeconfig`.

### Building the Controller

To build the controller locally.

```bash
make
```

### Building and Deploying to the `kind` Cluster

To build and deploy your image to the `kind` cluster:

```bash
./hack/cluster-sync.sh
```

### Testing

The project includes both unit tests and a full end-to-end (e2e) testing suite.

#### Unit Tests

To run the unit tests for all packages:

```bash
make test
```

I've tried to avoid creating lots of mocks for Unit Testing, so some testing is left for E2E for now.

#### End-to-End (e2e) Tests

We have full [documentation](../test/e2e/) on our E2E Tests.  

The e2e tests are located in `../test/e2e/`. Locally they use the `kind` cluster set up by the `cluster-up.sh` script. Don't forget to run `cluster-sync.sh` to deploy the controller inside `kind`. Each scenario is self-contained and tests a specific feature or behavior of the controller.  

To execute the scenario you can basically run `execute.sh` script inside scenarios directory.  

The output of each test is logged to the console, indicating the steps being performed and the results of the `nftables` verifications.

The e2e tests are also used in our CI/CD platform to perform automatic tests.