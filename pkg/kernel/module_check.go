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
package kernel

import (
	"os"
	"regexp"
	"strings"

	"k8s.io/klog/v2"
)

/* nftables kernel modules list */
var ourModules = []string{"nf_tables ", "nft_meta_bridge ", "nft_ct ", "nf_conntrack ", "bridge "}

/* check if modules are loaded */
func CheckNftables() bool {
	klog.V(8).Infof("Opening /proc/modules... \n")
	modules, err := os.ReadFile("/proc/modules")
	if err != nil {
		klog.Errorf("Error checking /proc/modules: %v \n", err)
		return false
	}

	klog.V(8).Infof("Matching modules on /proc/modules... \n")
	for id := range ourModules {
		klog.V(8).Infof("Matching module %s on /proc/modules... \n", strings.Trim(ourModules[id], " "))
		match, err := regexp.MatchString(ourModules[id], string(modules))
		if err != nil {
			klog.Errorf("Unable to match kernel module %s: %v \n", strings.Trim(ourModules[id], " "), err)
			return false
		}
		if !match {
			klog.Errorf("No %s module found on kernel. \n", strings.Trim(ourModules[id], " "))
			klog.Errorf("Make sure these modules are lodaded: %v \n", ourModules)
			return false
		}
		klog.V(8).Infof("Module %s found on /proc/modules... \n", strings.Trim(ourModules[id], " "))
	}
	klog.V(8).Infof("Finished matching all modules on /proc/modules...\n")
	return true
}
