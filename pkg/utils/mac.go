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
	"fmt"
	"net"
	"regexp"
	"strings"
)

/* macRegex is a regular expression for validating common MAC address formats.
 * Accepts XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, and XXXXXXXXXXXX.
 */
var macRegex = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|^([0-9A-Fa-f]{12})$`)

/* Converts a MAC string to net.HardwareAddr (which is a []byte). */
func ParseMAC(macStr string) (net.HardwareAddr, error) {
	if !macRegex.MatchString(macStr) {
		return nil, fmt.Errorf("invalid MAC address format: %s", macStr)
	}

	/* net.ParseMAC expects the format with delimiters (e.g., ":")
	 * If it's already in this format, great.
	 * If it's XXXXXXXXXXXX, we need to add the delimiters for net.ParseMAC to work,
	 * or manually parse to bytes. net.ParseMAC is safer.
	 */

	var parsableMacStr string
	switch {
	case strings.Contains(macStr, ":") || strings.Contains(macStr, "-"):
		parsableMacStr = macStr
	case len(macStr) == 12: /* XXXXXXXXXXXX format */
		/* insert ":" */
		var sb strings.Builder
		for i, r := range macStr {
			if i > 0 && i%2 == 0 {
				sb.WriteRune(':')
			}
			sb.WriteRune(r)
		}
		parsableMacStr = sb.String()
	default:
		return nil, fmt.Errorf("unhandled MAC address format after regex match: %s", macStr)
	}

	hwAddr, err := net.ParseMAC(parsableMacStr)
	if err != nil {
		return nil, fmt.Errorf("net.ParseMAC failed for '%s' (original '%s'): %w", parsableMacStr, macStr, err)
	}
	return hwAddr, nil
}
