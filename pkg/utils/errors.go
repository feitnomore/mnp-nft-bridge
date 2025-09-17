/**
 * Copyright 2025 Marcelo Parisi (github.com/feitnomore)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package utils

import (
	"strings"
)

func IsNftSetExistsError(err error) bool {
	if err == nil {
		return false
	}
	/* This message might vary based on nftables version or library specifics
	 * Convert both to lower case for case-insensitive comparison
	 */
	return strings.Contains(strings.ToLower(err.Error()), "file exists")
}

func IsNftNoSuchFileError(err error) bool {
	if err == nil {
		return false
	}
	/* This message might vary
	 * Convert both to lower case for case-insensitive comparison
	 */
	return strings.Contains(strings.ToLower(err.Error()), "no such file or directory")
}

func IsNftDeviceOrResourceBusyError(err error) bool {
	if err == nil {
		return false
	}
	/* This message might vary
	 * Convert both to lower case for case-insensitive comparison
	 */
	return strings.Contains(strings.ToLower(err.Error()), "device or resource busy")
}
