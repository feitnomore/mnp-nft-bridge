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

source ./hack/kind-common.sh
source ./hack/cilium.sh
source ./hack/kernel.sh
source ./hack/coredns.sh
source ./hack/multus.sh
source ./hack/multinetworkpolicy.sh

_kind_up()
{
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        export KUBECONFIG="./.work/kubeconfig"
        ${KIND} create cluster --config ${KIND_CONFIG} --retain --name=${CLUSTER_NAME}
        ./.work/bin/kubectl taint nodes --all node-role.kubernetes.io/control-plane-
    else
        echo "This should run from root path"
    fi
}

_kind_down()
{
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        ${KIND} delete clusters --name ${CLUSTER_NAME}
    else
        echo "This should run from root path"
    fi
}

_kind_generate_config() {
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        IMAGEVER=$(_kind_images)
        echo "kind: Cluster" > ${KIND_CONFIG}
        echo "apiVersion: kind.x-k8s.io/v1alpha4" >> ${KIND_CONFIG}
        echo "networking: " >> ${KIND_CONFIG}
        echo "  disableDefaultCNI: true" >> ${KIND_CONFIG}
        echo "nodes:" >> ${KIND_CONFIG}
        echo "- role: control-plane" >> ${KIND_CONFIG}
        echo "  image: ${IMAGEVER}" >> ${KIND_CONFIG}
        echo "  extraMounts:" >> ${KIND_CONFIG}
        echo "  - hostPath: /dev" >> ${KIND_CONFIG}
        echo "    containerPath: /dev" >> ${KIND_CONFIG}
        echo "    propagation: HostToContainer" >> ${KIND_CONFIG}
    else
        echo "This should run from root path"
    fi
}

_kind_ssh_node() {
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        MYNODE=`docker ps -a | grep mnp-nft-bridge-control | awk '{print $1}'`
        docker exec -it ${MYNODE} bash
    else
        echo "This should run from root path"
    fi
    
}

_kind_customize_nodes() {
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        curl -Lo ./.work/tmp/cni-plugins.tgz https://github.com/containernetworking/plugins/releases/download/v1.5.1/cni-plugins-linux-amd64-v1.5.1.tgz
        MYNODE=`docker ps -a | grep mnp-nft-bridge-control-plane | awk '{print $1}'`
        docker cp ./hack/customize-node.sh ${MYNODE}:/opt/customize-node.sh
        docker cp ./.work/tmp/cni-plugins.tgz ${MYNODE}:/opt/cni-plugins.tgz
        docker exec ${MYNODE} chmod +x /opt/customize-node.sh
        docker exec ${MYNODE} sh /opt/customize-node.sh
    else
        echo "This should run from root path"
    fi
    
}

_kind_images() {
    case "$KUBEVER" in
        v1.32)
            echo "kindest/node:v1.32.0@sha256:dbfe3fe9f25dc234af268f5ac9a945e421ac43a30df02acae8c98224523f89f1"
            ;;
        v1.31)
            echo "kindest/node:v1.31.0@sha256:53df588e04085fd41ae12de0c3fe4c72f7013bba32a20e7325357a1ac94ba865"
            ;;
        v1.30)
            echo "kindest/node:v1.30.4@sha256:976ea815844d5fa93be213437e3ff5754cd599b040946b5cca43ca45c2047114"
            ;;
        v1.29)
            echo "kindest/node:v1.29.8@sha256:d46b7aa29567e93b27f7531d258c372e829d7224b25e3fc6ffdefed12476d3aa"
            ;;
        v1.28)
            echo "kindest/node:v1.28.13@sha256:45d319897776e11167e4698f6b14938eb4d52eb381d9e3d7a9086c16c69a8110"
            ;;
        v1.27)
            echo "kindest/node:v1.27.17@sha256:3fd82731af34efe19cd54ea5c25e882985bafa2c9baefe14f8deab1737d9fabe"
            ;;
        *)
            echo "kindest/node:v1.30.4@sha256:976ea815844d5fa93be213437e3ff5754cd599b040946b5cca43ca45c2047114"
            ;;
    esac
}

if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] && [ -d .work ]
then
    _load_modules
    _kind_generate_config
    export KUBECONFIG="./.work/kubeconfig"
    _kind_up
    _kind_customize_nodes
    _apply_cilium
    _wait_cilium
    _wait_coredns
    #_get_multus
    _apply_multus
    #_get_multinetworkpolicy
    _apply_multinetworkpolicy
else
    echo "This should run from root path and you should run get-kind.sh first"
fi