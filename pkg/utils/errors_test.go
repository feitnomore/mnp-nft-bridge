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
	"errors"
	"fmt"
	"testing"
)

func TestIsNftSetExistsError(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "Nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "Standard 'File exists' error",
			err:      errors.New("some operation failed: File exists"),
			expected: true,
		},
		{
			name:     "Wrapped 'File exists' error",
			err:      fmt.Errorf("outer error: %w", errors.New("inner: File exists")),
			expected: true,
		},
		{
			name:     "Error message without 'File exists'",
			err:      errors.New("some other unrelated error"),
			expected: false,
		},
		{
			name:     "Error message with different casing", /* Robustness test for casing */
			err:      errors.New("operation status: file exists"),
			expected: true, /* strings.Contains is case-sensitive, so this would fail if casing mattered. */
		},
		{
			name:     "Error message with 'File exists' as part of a larger unrelated word",
			err:      errors.New("profileexists validation failed"), /* Ex: "profileexists" is not "File exists" */
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := IsNftSetExistsError(tc.err)
			if actual != tc.expected {
				t.Errorf("IsNftSetExistsError(%v): expected %v, got %v", tc.err, tc.expected, actual)
			}
		})
	}
}

func TestIsNftNoSuchFileError(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "Nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "Standard 'No such file or directory' error",
			err:      errors.New("failed to get resource: No such file or directory"),
			expected: true,
		},
		{
			name:     "Wrapped 'No such file or directory' error",
			err:      fmt.Errorf("context: %w", errors.New("detail: No such file or directory")),
			expected: true,
		},
		{
			name:     "Error message without 'No such file or directory'",
			err:      errors.New("permission denied"),
			expected: false,
		},
		{
			name:     "Error message with different casing",
			err:      errors.New("lookup failed: no such file or directory"),
			expected: true,
		},
		{
			name:     "Error message with 'No such file or directory' as part of a larger unrelated word",
			err:      errors.New("filenotfoundorcorrupt"),
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := IsNftNoSuchFileError(tc.err)
			if actual != tc.expected {
				t.Errorf("IsNftNoSuchFileError(%v): expected %v, got %v", tc.err, tc.expected, actual)
			}
		})
	}
}

func TestIsNftDeviceOrResourceBusyError(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "Nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "Standard 'device or resource busy' error",
			err:      errors.New("operation failed: device or resource busy"),
			expected: true,
		},
		{
			name:     "Wrapped 'device or resource busy' error",
			err:      fmt.Errorf("context: %w", errors.New("detail: device or resource busy")),
			expected: true,
		},
		{
			name:     "Error message without 'device or resource busy'",
			err:      errors.New("timeout occurred"),
			expected: false,
		},
		{
			name:     "Error message with different casing",
			err:      errors.New("NFT command error: Device or Resource Busy"),
			expected: true,
		},
		{
			name:     "Error message with substring as part of a larger unrelated word",
			err:      errors.New("thedeviceorresourcebusyflagisnotset"),
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := IsNftDeviceOrResourceBusyError(tc.err)
			if actual != tc.expected {
				t.Errorf("IsNftDeviceOrResourceBusyError(%v): expected %v, got %v", tc.err, tc.expected, actual)
			}
		})
	}
}
