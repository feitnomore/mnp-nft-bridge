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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMAC(t *testing.T) {
	tests := []struct {
		name        string
		macStr      string
		expectedMAC net.HardwareAddr
		expectError bool
	}{
		{
			name:        "Valid MAC with colons",
			macStr:      "00:1A:2B:3C:4D:5E",
			expectedMAC: net.HardwareAddr{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e},
			expectError: false,
		},
		{
			name:        "Valid MAC with hyphens",
			macStr:      "aa-bb-cc-dd-ee-ff",
			expectedMAC: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			expectError: false,
		},
		{
			name:        "Valid MAC without delimiters",
			macStr:      "0123456789AB",
			expectedMAC: net.HardwareAddr{0x01, 0x23, 0x45, 0x67, 0x89, 0xab},
			expectError: false,
		},
		{
			name:        "Valid MAC lowercase",
			macStr:      "00:1a:2b:3c:4d:5e",
			expectedMAC: net.HardwareAddr{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e},
			expectError: false,
		},
		{
			name:        "Invalid MAC - too short",
			macStr:      "00:1A:2B:3C:4D",
			expectError: true,
		},
		{
			name:        "Invalid MAC - too long",
			macStr:      "00:1A:2B:3C:4D:5E:6F",
			expectError: true,
		},
		{
			name:        "Invalid MAC - invalid characters",
			macStr:      "00:1A:2B:3G:4D:5E",
			expectError: true,
		},
		{
			name:        "Invalid MAC - no delimiters, wrong length",
			macStr:      "0123456789A",
			expectError: true,
		},
		{
			name:        "Empty string",
			macStr:      "",
			expectError: true,
		},
		{
			name:        "Mixed delimiters (invalid by regex)",
			macStr:      "00:1A-2B:3C-4D:5E",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hwAddr, err := ParseMAC(tt.macStr)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, hwAddr)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, hwAddr)
				assert.Equal(t, tt.expectedMAC.String(), hwAddr.String())
			}
		})
	}
}
