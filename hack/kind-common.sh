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

OUT_DIR="./.work"
KIND="$OUT_DIR/bin/kind"
CLUSTER_NAME="mnp-nft-bridge"
EXAMPLES="./hack/examples"
KIND_CONFIG="$OUT_DIR/tmp/config.yaml"
KUBECTL_VERSION="v1.30.3"
CRICTL_VERSION="v1.31.1"
KIND_VERSION="v0.24.0"
CALICO_VERSION="v3.28.1"
CALICO_DL="https://raw.githubusercontent.com/projectcalico/calico"
KIND_DL="https://kind.sigs.k8s.io/dl"
KUBECTL_DL="https://dl.k8s.io/release"
JQ_DL="https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-amd64"
JQ_VERSION="jq-1.7.1"
GOLINT_DL="https://raw.githubusercontent.com/golangci/golangci-lint"
CRICTL_DL="https://github.com/kubernetes-sigs/cri-tools/releases/download"
GOLINT_VERSION="latest"
GOLINT="$OUT_DIR/bin/golangci-lint"
GO_DL="https://go.dev/dl"
GO_VERSION="go1.23.2"
GO="$OUT_DIR/bin/go"
GOFMT="$OUT_DIR/bin/gofmt"
HELM_VERSION="v3.15.4"
HELM_DL="https://get.helm.sh"
HELM="$OUT_DIR/bin/helm"
DOCKER_BIN=`which docker`

if [ -z "$KIND_ID" ] && [ -z "$LANE" ]
then
    KIND_ID=`docker ps | grep kindest | grep mnp-nft-bridge-control-plane | awk '{print $1}' 2>&1 > /dev/null`
else
    KIND_ID="cicd"
fi

if [ -z "$LANE" ]
then
    CONTROL_PLANE_IP=`docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ${KIND_ID} 2>&1 > /dev/null`
else
    CONTROL_PLANE_IP="127.0.0.1"
fi

_create_work() {
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        mkdir -p ${OUT_DIR}/bin
        mkdir -p ${OUT_DIR}/tmp
        mkdir -p ${OUT_DIR}/go
    else
        echo "This should run from root path"
    fi
}