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
	"testing"

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	utilsPodNetworksAnnot      = netdefv1.NetworkAttachmentAnnot
	utilsPodNetworkStatusAnnot = netdefv1.NetworkStatusAnnot
)

func TestPodMultiNetworkUtil(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		expected    bool
	}{
		{
			name:        "No annotations",
			annotations: nil,
			expected:    false,
		},
		{
			name:        "Only networks annotation (no status)",
			annotations: map[string]string{utilsPodNetworksAnnot: "net1,net2"},
			expected:    false,
		},
		{
			name:        "Empty network status annotation",
			annotations: map[string]string{utilsPodNetworksAnnot: "net1,net2", utilsPodNetworkStatusAnnot: ""},
			expected:    false,
		},
		{
			name:        "Malformed JSON network status",
			annotations: map[string]string{utilsPodNetworksAnnot: "net1,net2", utilsPodNetworkStatusAnnot: "[{\"name\":\"net1\""},
			expected:    false,
		},
		{
			name:        "Single network in status",
			annotations: map[string]string{utilsPodNetworksAnnot: "net1", utilsPodNetworkStatusAnnot: `[{"name":"net1","interface":"eth0"}]`},
			expected:    false,
		},
		{
			name:        "Multiple networks in status",
			annotations: map[string]string{utilsPodNetworksAnnot: "net1,net2", utilsPodNetworkStatusAnnot: `[{"name":"net1","interface":"eth0"},{"name":"net2","interface":"eth1"}]`},
			expected:    true,
		},
		{
			name:        "Network status is not an array",
			annotations: map[string]string{utilsPodNetworksAnnot: "net1", utilsPodNetworkStatusAnnot: `{"name":"net1"}`},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: tt.annotations}}
			assert.Equal(t, tt.expected, PodMultiNetwork(pod))
		})
	}
}

func TestPodMultiNetworkNameUtil(t *testing.T) {
	tests := []struct {
		name                 string
		podNamespace         string
		annotations          map[string]string
		expectedNetNamespace string
		expectedNetName      string
	}{
		{
			name:                 "No annotations",
			podNamespace:         "default",
			annotations:          nil,
			expectedNetNamespace: "",
			expectedNetName:      "",
		},
		{
			name:                 "Single network in status",
			podNamespace:         "default",
			annotations:          map[string]string{utilsPodNetworkStatusAnnot: `[{"name":"net1"}]`},
			expectedNetNamespace: "",
			expectedNetName:      "",
		},
		{
			name:         "Multiple networks, second has namespace",
			podNamespace: "default",
			annotations: map[string]string{
				utilsPodNetworksAnnot:      "net1,custom-ns/secondary-net",
				utilsPodNetworkStatusAnnot: `[{"name":"kube-system/kindnet"}, {"name":"custom-ns/secondary-net"}]`,
			},
			expectedNetNamespace: "custom-ns",
			expectedNetName:      "secondary-net",
		},
		{
			name:         "Multiple networks, second no namespace (current impl behavior)",
			podNamespace: "app-ns",
			annotations: map[string]string{
				utilsPodNetworksAnnot:      "net1,secondary-net-no-ns",
				utilsPodNetworkStatusAnnot: `[{"name":"kube-system/kindnet"}, {"name":"secondary-net-no-ns"}]`,
			},
			expectedNetNamespace: "",
			expectedNetName:      "",
		},
		{
			name:         "Multiple networks, second name is just /name",
			podNamespace: "app-ns",
			annotations: map[string]string{
				utilsPodNetworksAnnot:      "net1,/secondary-net-slash",
				utilsPodNetworkStatusAnnot: `[{"name":"kube-system/kindnet"}, {"name":"/secondary-net-slash"}]`,
			},
			expectedNetNamespace: "",
			expectedNetName:      "secondary-net-slash",
		},
		{
			name:         "Network status has only one entry",
			podNamespace: "app-ns",
			annotations: map[string]string{
				utilsPodNetworksAnnot:      "net1",
				utilsPodNetworkStatusAnnot: `[{"name":"kube-system/kindnet"}]`,
			},
			expectedNetNamespace: "",
			expectedNetName:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: tt.podNamespace, Annotations: tt.annotations}}
			ns, name := PodMultiNetworkName(pod)
			assert.Equal(t, tt.expectedNetNamespace, ns, "Namespace mismatch")
			assert.Equal(t, tt.expectedNetName, name, "Name mismatch")
		})
	}
}

func TestPodBridgeInterfaceAndMacAddrUtil(t *testing.T) {
	tests := []struct {
		name              string
		annotations       map[string]string
		expectedInterface string
		expectedMac       string
	}{
		{
			name:              "No annotations",
			annotations:       nil,
			expectedInterface: "",
			expectedMac:       "",
		},
		{
			name:              "Single network in status",
			annotations:       map[string]string{utilsPodNetworkStatusAnnot: `[{"name":"net1"}]`},
			expectedInterface: "",
			expectedMac:       "",
		},
		{
			name: "Multiple networks, second has iface and mac",
			annotations: map[string]string{
				utilsPodNetworksAnnot:      "net1,net2",
				utilsPodNetworkStatusAnnot: `[{"name":"net1"}, {"name":"net2","interface":"br-eth1","mac":"00:AA:BB:CC:DD:EE"}]`,
			},
			expectedInterface: "br-eth1",
			expectedMac:       "00:AA:BB:CC:DD:EE",
		},
		{
			name: "Multiple networks, second missing mac",
			annotations: map[string]string{
				utilsPodNetworksAnnot:      "net1,net2",
				utilsPodNetworkStatusAnnot: `[{"name":"net1"}, {"name":"net2","interface":"br-eth2"}]`,
			},
			expectedInterface: "br-eth2",
			expectedMac:       "",
		},
		{
			name: "Multiple networks, second missing interface",
			annotations: map[string]string{
				utilsPodNetworksAnnot:      "net1,net2",
				utilsPodNetworkStatusAnnot: `[{"name":"net1"}, {"name":"net2","mac":"11:22:33:44:55:66"}]`,
			},
			expectedInterface: "",
			expectedMac:       "11:22:33:44:55:66",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: tt.annotations}}
			iface, mac := PodBridgeInterfaceAndMacAddr(pod)
			assert.Equal(t, tt.expectedInterface, iface, "Interface mismatch")
			assert.Equal(t, tt.expectedMac, mac, "MAC address mismatch")
		})
	}
}

func TestPodMacVlanInterfaceAndIPAddrUtil(t *testing.T) {
	tests := []struct {
		name              string
		annotations       map[string]string
		expectedInterface string
		expectedIP        string
		expectPanic       bool
	}{
		{
			name:              "No annotations",
			annotations:       nil,
			expectedInterface: "",
			expectedIP:        "",
			expectPanic:       false,
		},
		{
			name:              "Single network in status",
			annotations:       map[string]string{utilsPodNetworkStatusAnnot: `[{"name":"net1"}]`},
			expectedInterface: "",
			expectedIP:        "",
			expectPanic:       false,
		},
		{
			name: "Multiple networks, second has iface and IP",
			annotations: map[string]string{
				utilsPodNetworksAnnot:      "net1,net2",
				utilsPodNetworkStatusAnnot: `[{"name":"net1"}, {"name":"net2","interface":"macvlan0","ips":["192.168.1.100"]}]`,
			},
			expectedInterface: "macvlan0",
			expectedIP:        "192.168.1.100",
			expectPanic:       false,
		},
		{
			name: "Multiple networks, second has iface and multiple IPs (takes first)",
			annotations: map[string]string{
				utilsPodNetworksAnnot:      "net1,net2",
				utilsPodNetworkStatusAnnot: `[{"name":"net1"}, {"name":"net2","interface":"macvlan1","ips":["10.0.0.5", "2001:db8::1"]}]`,
			},
			expectedInterface: "macvlan1",
			expectedIP:        "10.0.0.5",
			expectPanic:       false,
		},
		{
			name: "Multiple networks, second missing IPs (causes panic because statuses[1].IPs is nil)",
			annotations: map[string]string{
				utilsPodNetworksAnnot:      "net1,net2",
				utilsPodNetworkStatusAnnot: `[{"name":"net1"}, {"name":"net2","interface":"macvlan2"}]`,
			},
			expectedInterface: "macvlan2",
			expectedIP:        "",
			expectPanic:       true,
		},
		{
			name: "Multiple networks, second has empty IPs array (causes panic because len is 0)",
			annotations: map[string]string{
				utilsPodNetworksAnnot:      "net1,net2",
				utilsPodNetworkStatusAnnot: `[{"name":"net1"}, {"name":"net2","interface":"macvlan3", "ips":[]}]`,
			},
			expectedInterface: "macvlan3",
			expectedIP:        "",
			expectPanic:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: tt.annotations}}
			if tt.expectPanic {
				assert.Panics(t, func() {
					PodMacVlanInterfaceAndIPAddr(pod)
				}, "Expected PodMacVlanInterfaceAndIPAddr to panic for case: %s", tt.name)
			} else {
				iface, ip := PodMacVlanInterfaceAndIPAddr(pod)
				assert.Equal(t, tt.expectedInterface, iface, "Interface mismatch")
				assert.Equal(t, tt.expectedIP, ip, "IP address mismatch")
			}
		})
	}
}
