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


# Check if SCENARIO_DIR is null or empty
if [[ -z "$SCENARIO_DIR" ]]; then
  BIN_DIR="./.work/bin" # Path if SCENARIO_DIR is blank or null
  WORK_DIR="./.work"
else
  BIN_DIR="../../../../.work/bin" # Path if SCENARIO_DIR exists and is not blank
  WORK_DIR="../../../../.work"
fi

export KUBECONFIG="${WORK_DIR}/kubeconfig"
${BIN_DIR}/kubectl $@
