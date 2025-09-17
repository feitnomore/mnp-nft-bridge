
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
source ./hack/kernel.sh

_get_kind()
{
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        # For AMD64 / x86_64
        [ $(uname -m) = x86_64 ] && curl -Lo ${OUT_DIR}/bin/kind ${KIND_DL}/${KIND_VERSION}/kind-linux-amd64
        # For ARM64
        [ $(uname -m) = aarch64 ] && curl -Lo ${OUT_DIR}/bin/kind ${KIND_DL}/${KIND_VERSION}/kind-linux-arm64
        chmod +x ./.work/bin/kind
    else
        echo "This should run from root path"
    fi
}

_get_kubectl()
{
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        # For AMD64 / x86_64
        [ $(uname -m) = x86_64 ] && curl -Lo ${OUT_DIR}/bin/kubectl ${KUBECTL_DL}/${KUBECTL_VERSION}/bin/linux/amd64/kubectl
        # For ARM64
        [ $(uname -m) = aarch64 ] && curl -Lo ${OUT_DIR}/bin/kubectl ${KUBECTL_DL}/${KUBECTL_VERSION}/linux/arm64/kubectl
        chmod +x ./.work/bin/kubectl
    else
        echo "This should run from root path"
    fi
}

_get_jq()
{
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        # For AMD64 / x86_64
        [ $(uname -m) = x86_64 ] && curl -Lo ${OUT_DIR}/bin/jq ${JQ_DL}/${JQ_VERSION}/jq-linux-amd64
        # For ARM64
        [ $(uname -m) = aarch64 ] && curl -Lo ${OUT_DIR}/bin/jq ${JQ_DL}/${JQ_VERSION}/jq-linux-arm64
        chmod +x ./.work/bin/jq
    else
        echo "This should run from root path"
    fi
}

_get_golang() {
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        # For AMD64 / x86_64
        if [ $(uname -m) = x86_64 ] 
        then
            curl -Lo ${OUT_DIR}/tmp/go.tar.gz ${GO_DL}/${GO_VERSION}.linux-amd64.tar.gz
            cd ${OUT_DIR}/ && tar -xzf ./tmp/go.tar.gz && rm -rf ./tmp/go.tar.gz && cd ../
        # For ARM64
        elif [ $(uname -m) = aarch64 ]
        then
            curl -Lo ${OUT_DIR}/tmp/go.tar.gz ${GO_DL}/${GO_VERSION}.linux-arm64.tar.gz
            cd ${OUT_DIR}/ && tar -xzf ./tmp/go.tar.gz && -rf ./tmp/go.tar.gz && cd ../
        fi
    else
        echo "This should run from root path"
    fi
}

_get_golint()
{
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        curl -sSfL ${GOLINT_DL}/master/install.sh | sh -s -- -b ${OUT_DIR}/bin ${GOLINT_VERSION}
    else
        echo "This should run from root path"
    fi
}

_get_crictl()
{
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        # For AMD64 / x86_64
        if [ $(uname -m) = x86_64 ] 
        then
            curl -Lo ${OUT_DIR}/tmp/crictl.tar.gz ${CRICTL_DL}/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-amd64.tar.gz
            cd ${OUT_DIR}/bin && tar -xzf ../tmp/crictl.tar.gz && rm -rf ../tmp/crictl.tar.gz && chmod +x ./crictl && cd ../../
        # For ARM64
        elif [ $(uname -m) = aarch64 ]
        then
            curl -Lo ${OUT_DIR}/tmp/crictl.tar.gz ${CRICTL_DL}/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-arm64.tar.gz
            cd ${OUT_DIR}/bin && tar -xzf ../tmp/crictl.tar.gz && rm -rf ../tmp/crictl.tar.gz && chmod +x ./crictl && cd ../../
        fi
    else
        echo "This should run from root path"
    fi
}

_get_helm()
{
    if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
    then
        # For AMD64 / x86_64
        if [ $(uname -m) = x86_64 ] 
        then
            curl -Lo ${OUT_DIR}/tmp/helm.tar.gz ${HELM_DL}/helm-${HELM_VERSION}-linux-amd64.tar.gz
            cd ${OUT_DIR}/tmp && tar -xzf helm.tar.gz && rm -rf helm.tar.gz && mv linux-amd64/helm ../bin/helm && chmod +x ../bin/helm && cd ../
        # For ARM64
        elif [ $(uname -m) = aarch64 ]
        then
            curl -Lo ${OUT_DIR}/tmp/helm.tar.gz ${HELM_DL}/helm-${HELM_VERSION}-linux-arm64.tar.gz
            cd ${OUT_DIR}/tmp && tar -xzf helm.tar.gz && rm -rf helm.tar.gz && mv linux-amd64/helm ../bin/helm && chmod +x ../bin/helm && cd ../
        fi
    else
        echo "This should run from root path"
    fi
}

if [ -f LICENSE ] &&  [ -f go.mod ] && [ -f go.sum ] 
then
    _create_work
    _get_kind
    _get_kubectl
    _get_jq
    _get_golang
    _get_golint
    _get_helm
    _load_modules
else
    echo "This should run from root path"
fi