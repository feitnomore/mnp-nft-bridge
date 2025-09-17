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
package handler

import (
	"reflect"

	"github.com/feitnomore/mnp-nft-bridge/pkg/cache"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	"k8s.io/klog/v2"
)

/* Event: Added MultiNetworkPolicy */
func AddMultinetPolicy(multipolicy *multiv1beta1.MultiNetworkPolicy) bool {
	if !cache.MultiNetworkPolicyExistsInCache(multipolicy.Namespace, multipolicy.Name) {
		cache.AddMultiNetworkPolicy(multipolicy)
		klog.V(8).Infof("Multi Network Policy added: %s in namespace: %s\n", multipolicy.Name, multipolicy.Namespace)
		/* Need reconcile */
		return true
	}
	/* Doesn't need reconcile */
	return false
}

/* Event: Updated MultiNetworkPolicy */
func UpdateMultinetPolicy(multipolicy *multiv1beta1.MultiNetworkPolicy) bool {
	if cache.MultiNetworkPolicyExistsInCache(multipolicy.Namespace, multipolicy.Name) {
		klog.V(8).Infof("Multi Network Policy updted: %s in namespace: %s\n", multipolicy.Name, multipolicy.Namespace)
		actualMultinet := cache.GetMultiNetworkPolicyFromCache(multipolicy.Namespace, multipolicy.Name)
		if !reflect.DeepEqual(actualMultinet.Spec, multipolicy.Spec) || !reflect.DeepEqual(actualMultinet.Labels, multipolicy.Labels) || !reflect.DeepEqual(actualMultinet.Annotations, multipolicy.Annotations) {
			klog.V(8).Infof("MultiNetworkPolicy changed, updating....")
			cache.DeleteMultiNetworkPolicyFromCache(multipolicy.Name, multipolicy.Namespace)
			cache.AddMultiNetworkPolicy(multipolicy)
			return true
		}
	} else {
		AddMultinetPolicy(multipolicy)
		return true
	}
	/* Doesn't need reconcile */
	return false
}

/* Event: Deleted MultiNetworkPolicy */
func DeleteMultinetPolicy(multipolicy *multiv1beta1.MultiNetworkPolicy) bool {
	klog.V(8).Infof("Multi Network Policy deleted: %s in namespace: %s\n", multipolicy.Name, multipolicy.Namespace)
	cache.DeleteMultiNetworkPolicyFromCache(multipolicy.Name, multipolicy.Namespace)
	/* Need reconcile */
	return true
}
