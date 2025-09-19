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

## CI/CD

The CI/CD artifacts related to this repo are in [mnp-nft-bridge-infra](https://github.com/kubevirt-manager/mnp-nft-bridge-infra/).  
Our CI/CD portal is [cicd.kubevirt-manager.io](https://cicd.kubevirt-manager.io/).  
The solution is heavily based on [Tekton](https://tekton.dev/).