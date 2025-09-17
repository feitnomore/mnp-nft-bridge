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

if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
then
    VERSION="dev"
    ./hack/clean-docker.sh
    ./hack/kubectl.sh delete -f ./charts/deploy.yaml
    CID=`docker ps | grep "mnp-nft-bridge-control-plane" | awk '{print $1}'`
    docker exec ${CID} ctr -n=k8s.io images rm docker.io/library/mnp-nft-bridge:${VERSION}  
    make local-image-build
    ${KIND} load docker-image mnp-nft-bridge:${VERSION} --name ${CLUSTER_NAME}
    ./hack/kubectl.sh apply -f ./charts/deploy.yaml
    ./hack/kubectl.sh set image ds/mnp-nft-bridge mnp-nft-bridge=mnp-nft-bridge:${VERSION} -n kube-system
    sleep 5s
    NFT_POD=`./hack/kubectl.sh get pods -n kube-system | grep "mnp-nft-bridge" | grep -v "etcd" | grep -v "kube" | awk '{print $1}'`
    ./hack/kubectl.sh wait --for=condition=Ready --timeout=300s pod/${NFT_POD} -n kube-system

else
    echo "This should run from root path"
fi
