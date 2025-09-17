
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

# Verifica se SCENARIO_DIR é nulo ou vazio
if [[ -z "$SCENARIO_DIR" ]]; then
  OUR_HACK="./hack"
else
  OUR_HACK="${SCENARIO_DIR}/../../../../hack"
fi
source ${OUR_HACK}/kind-common.sh

${DOCKER_BIN} exec ${KIND_ID} $@

