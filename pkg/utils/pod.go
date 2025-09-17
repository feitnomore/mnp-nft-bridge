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

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

/* Check if Pod has Multinetwork */
func PodMultiNetwork(pod *v1.Pod) bool {
	_, err := netdefutils.ParsePodNetworkAnnotation(pod)
	if err != nil {
		if _, ok := err.(*netdefv1.NoK8sNetworkError); !ok {
			klog.Errorf("failed to get pod network annotation: %v", err)
		}
	}
	/* Parse Network Statuses */
	statuses, _ := netdefutils.GetNetworkStatus(pod)
	return len(statuses) > 1
}

/* Get Pod Network Name */
func PodMultiNetworkName(pod *v1.Pod) (string, string) {
	netName := ""
	netNamespace := ""
	_, err := netdefutils.ParsePodNetworkAnnotation(pod)
	if err != nil {
		if _, ok := err.(*netdefv1.NoK8sNetworkError); !ok {
			klog.Errorf("failed to get pod network annotation: %v", err)
		}
	}

	/* Parse Network Statuses */
	statuses, err := netdefutils.GetNetworkStatus(pod)
	if err != nil {
		klog.Errorf("Error getting network status: %v", err)
	}

	if len(statuses) > 1 {
		slashItems := strings.Split(statuses[1].Name, "/")
		if len(slashItems) == 2 {
			netNamespace = strings.TrimSpace(slashItems[0])
			netName = slashItems[1]
		}
	}

	return netNamespace, netName
}

/* Get bridge interface and macaddr */
func PodBridgeInterfaceAndMacAddr(pod *v1.Pod) (string, string) {
	bridgeIface := ""
	bridgeMacAddr := ""
	_, err := netdefutils.ParsePodNetworkAnnotation(pod)
	if err != nil {
		if _, ok := err.(*netdefv1.NoK8sNetworkError); !ok {
			klog.Errorf("failed to get pod network annotation: %v", err)
		}
	}

	/* Parse Network Statuses */
	statuses, err := netdefutils.GetNetworkStatus(pod)
	if err != nil {
		klog.Errorf("Error getting network status: %v", err)
	}

	if len(statuses) > 1 {
		bridgeIface = statuses[1].Interface
		bridgeMacAddr = statuses[1].Mac
	}

	return bridgeIface, bridgeMacAddr
}

/* Get macvlan interface and IP Addr */
func PodMacVlanInterfaceAndIPAddr(pod *v1.Pod) (string, string) {
	macvlanIface := ""
	macvlanIPAddr := ""
	_, err := netdefutils.ParsePodNetworkAnnotation(pod)
	if err != nil {
		if _, ok := err.(*netdefv1.NoK8sNetworkError); !ok {
			klog.Errorf("failed to get pod network annotation: %v", err)
		}
	}

	/* Parse Network Statuses */
	statuses, err := netdefutils.GetNetworkStatus(pod)
	if err != nil {
		klog.Errorf("Error getting network status: %v", err)
	}

	if len(statuses) > 1 {
		macvlanIface = statuses[1].Interface
		macvlanIPAddr = statuses[1].IPs[0]
	}

	return macvlanIface, macvlanIPAddr
}
