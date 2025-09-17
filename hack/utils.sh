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

# Colors for logs
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_BLUE='\033[0;34m'
COLOR_NC='\033[0m' # No Color

log_info() {
    echo -e "${COLOR_BLUE}INFO: $1${COLOR_NC}" >&2 # Redirect to STDERR
}

log_success() {
    echo -e "${COLOR_GREEN}SUCCESS: $1${COLOR_NC}" >&2 # Redirect to STDERR
}

log_warn() {
    echo -e "${COLOR_YELLOW}WARN: $1${COLOR_NC}" >&2 # Redirect to STDERR
}

log_error() {
    echo -e "${COLOR_RED}ERROR: $1${COLOR_NC}" >&2 # Redirect to STDERR
}