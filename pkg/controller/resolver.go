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
package controller // Now in the controller package

import (
	"github.com/feitnomore/mnp-nft-bridge/pkg/cache"
	"github.com/feitnomore/mnp-nft-bridge/pkg/types"
	"github.com/feitnomore/mnp-nft-bridge/pkg/utils"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

/* ResolveMacListForPods retrieves MAC addresses for pods in a list that are running
 * and attached to a "bridge" CNI network.
 * This function now resides in the controller package as it needs access to the cache.
 */
func ResolveMacListForPods(podList *v1.PodList) []string {
	var macList []string
	if podList == nil {
		klog.Warningf("ResolveMacListForPods called with a nil PodList.")
		return nil
	}

	klog.V(5).Infof("ResolveMacListForPods: Processing %d pods.", len(podList.Items))
	for i := range podList.Items {
		/* Making a local copy of the pod object */
		pod := podList.Items[i]

		klog.V(7).Infof("[ResolveMacListForPods] Processing pod %s/%s, Phase: %s", pod.Namespace, pod.Name, pod.Status.Phase)
		/* Use the constant v1.PodRunning */
		if pod.Status.Phase == v1.PodRunning {
			/* Pass pointer to the local copy */
			netNamespace, netName := utils.PodMultiNetworkName(&pod)

			if netName == "" {
				klog.V(7).Infof("[ResolveMacListForPods] Pod %s/%s does not have a resolvable secondary network name from annotations.", pod.Namespace, pod.Name)
				continue
			}

			netDriver := cache.GetNetworkAttachmentDefinitionDriver(netNamespace, netName)
			klog.V(7).Infof("[ResolveMacListForPods] Pod %s/%s, Network: %s/%s, Detected Driver: '%s'", pod.Namespace, pod.Name, netNamespace, netName, netDriver)

			/* BridgeDriver is a const defined in pkg/controller/constants.go */
			if netDriver == types.CNIDriverBridge {
				_, podMac := utils.PodBridgeInterfaceAndMacAddr(&pod)
				if podMac != "" {
					macList = append(macList, podMac)
					klog.V(6).Infof("[ResolveMacListForPods] Added MAC %s for pod %s/%s (network: %s/%s, driver: %s)", podMac, pod.Namespace, pod.Name, netNamespace, netName, netDriver)
				} else {
					klog.V(6).Infof("[ResolveMacListForPods] Pod %s/%s on bridge network %s/%s has no MAC address in its network status.", pod.Namespace, pod.Name, netNamespace, netName)
				}
			} else {
				klog.V(7).Infof("[ResolveMacListForPods] Pod %s/%s on network %s/%s uses driver '%s', not '%s'. Skipping MAC.", pod.Namespace, pod.Name, netNamespace, netName, netDriver, types.CNIDriverBridge)
			}
		} else {
			klog.V(7).Infof("[ResolveMacListForPods] Pod %s/%s is not in Running phase (current: %s). Skipping MAC.", pod.Namespace, pod.Name, pod.Status.Phase)
		}
	}
	klog.V(5).Infof("ResolveMacListForPods: Finished processing. Found %d MACs: %v", len(macList), macList)
	return macList
}
