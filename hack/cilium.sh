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

_apply_cilium()
{
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        ./hack/kubectl.sh create -f ./hack/examples/cilium-1.14.13.yaml
        sleep 10s
    else
        echo "This should run from root path"
    fi
}

_wait_cilium()
{
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        CILIUM_NS="kube-system"
        CILIUM_POD=`./hack/kubectl.sh get pods -n ${CILIUM_NS} | grep cilium | grep -v operator | awk '{print $1}'`
        ./hack/kubectl.sh wait --for=condition=Ready --timeout=300s pod/${CILIUM_POD} -n ${CILIUM_NS}
    else
        echo "This should run from root path"
    fi
}