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
package controller

import (
	"context"
	"time"

	"github.com/feitnomore/mnp-nft-bridge/pkg/handler"
	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	multiclient "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

/* Controller to handle MultiNetworkPolicy */
type MultiNetworkPolicyController struct {
	clientset *multiclient.Clientset
}

/* Creates an instance of our Controller */
func NewMultiNetworkPolicyController() (*MultiNetworkPolicyController, error) {
	/* Getting Cluster Config */
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	/* Kubernetes Client */
	clientset, err := multiclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &MultiNetworkPolicyController{clientset: clientset}, nil
}

/* Controller Runner */
func (c *MultiNetworkPolicyController) Run(stopCh <-chan struct{}) error {

	/* Creating a MultiNetworkPolicy Informer */
	multiPolicyInformer := cache.NewSharedInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return c.clientset.K8sCniCncfIoV1beta1().MultiNetworkPolicies("").List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return c.clientset.K8sCniCncfIoV1beta1().MultiNetworkPolicies("").Watch(context.TODO(), options)
			},
		},
		&multiv1beta1.MultiNetworkPolicy{}, 0*time.Second)

	/* Adding MultiNetworkPolicy Handlers to Add, Update and Delete */
	_, err := multiPolicyInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			mNp := obj.(*multiv1beta1.MultiNetworkPolicy)
			if handler.AddMultinetPolicy(mNp) {
				ForceReconcile()
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldNp := oldObj.(*multiv1beta1.MultiNetworkPolicy)
			_ = oldNp
			newNp := newObj.(*multiv1beta1.MultiNetworkPolicy)
			if handler.UpdateMultinetPolicy(newNp) {
				ForceReconcile()
			}
		},
		DeleteFunc: func(obj interface{}) {
			nNp := obj.(*multiv1beta1.MultiNetworkPolicy)
			if handler.DeleteMultinetPolicy(nNp) {
				ForceReconcile()
			}
		},
	})

	if err != nil {
		klog.Errorf("Error adding MultiNetworkPolicy handlers: %v\n", err)
		return err
	}

	/* Start MultiNetworkPolicy Informer */
	go multiPolicyInformer.Run(stopCh)

	/* Waiting for sync */
	if !cache.WaitForCacheSync(stopCh, multiPolicyInformer.HasSynced) {
		klog.Errorf("failed to sync informers")
		return nil
	}

	return nil
}
