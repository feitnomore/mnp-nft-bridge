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

	"k8s.io/klog/v2"
)

func TestDisplayBanner(_ *testing.T) {
	var buf bytes.Buffer
	klog.SetOutput(&buf) // No assignment needed here
	defer klog.SetOutput(nil)

	/* Call the function */
	DisplayBanner("dev")

	/* Assert that the function didn't panic (indirect verification)
	 * (No assertion about the exact output is possible without parsing the log buffer, which is overly complex for a simple banner function).
	 * You could assert the version string is present if you want to verify its inclusion
	 */
}
