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
	"k8s.io/klog/v2"
)

/* Display a banner because we are cool */
func DisplayBanner(version string) {
	klog.Infof("\n")
	klog.Infof("                                     __ _          _          _     _                \n")
	klog.Infof("                                    / _| |        | |        (_)   | |               \n")
	klog.Infof("  _ __ ___  _ __  _ __ ______ _ __ | |_| |_ ______| |__  _ __ _  __| | __ _  ___     \n")
	klog.Infof(" | '_ ` _ \\| '_ \\| '_ \\______| '_ \\|  _| __|______| '_ \\| '__| |/ _` |/ _` |/ _ \\    \n")
	klog.Infof(" | | | | | | | | | |_) |     | | | | | | |_       | |_) | |  | | (_| | (_| |  __/    \n")
	klog.Infof(" |_| |_| |_|_| |_| .__/      |_| |_|_|  \\__|      |_.__/|_|  |_|\\__,_|\\__, |\\___|    \n")
	klog.Infof("                 | |                                                   __/ |         \n")
	klog.Infof("                 |_|                                                  |___/          \n")
	klog.Infof("\n")
	klog.Infof("                                     Version: %s", version)
	klog.Infof("\n")
}
