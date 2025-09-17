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
	"bytes"
	"testing"
)

func TestIfname(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "Short interface name",
			input:    "eth0",
			expected: []byte("eth0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		},
		{
			name:     "Medium interface name",
			input:    "wlan0-long",
			expected: []byte("wlan0-long\x00\x00\x00\x00\x00\x00"),
		},
		{
			name:     "Empty interface name",
			input:    "",
			expected: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		},
		{
			name:     "Interface name with exactly 15 chars",
			input:    "abcdefghijklmno", /* 15 chars */
			expected: []byte("abcdefghijklmno\x00"),
		},
		{
			name:  "Interface name with 16 chars",
			input: "abcdefghijklmnop", /* 16 chars */
			/* []byte("abcdefghijklmnop" + "\x00") has 17 bytes. copy will get the first 16. */
			expected: []byte("abcdefghijklmnop"),
		},
		{
			name:  "Interface name longer than 16 chars",
			input: "abcdefghijklmnopqrstuvwxyz", /* 26 chars */
			/* []byte("abcdefghijklmnopqrstuvwxyz" + "\x00") is 27 bytes. copy will get the first 16. */
			expected: []byte("abcdefghijklmnop"),
		},
		{
			name:  "Interface name with null character in middle",
			input: "eth\x00dev",
			/* []byte("eth\x00dev" + "\x00") -> [101, 116, 104, 0, 100, 101, 118, 0]
			 * The remainder of the 16-byte buffer will be filled with zeros.
			 */
			expected: []byte{101, 116, 104, 0, 100, 101, 118, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := Ifname(tc.input)
			if len(actual) != 16 {
				t.Errorf("Input: '%s'\nExpected length: 16\nGot length: %d", tc.input, len(actual))
			}
			if !bytes.Equal(actual, tc.expected) {
				t.Errorf("Input: '%s'\nExpected: %#v\nGot:      %#v",
					tc.input, tc.expected, actual)
			}
		})
	}
}
