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
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

/* Controller to handle NetworkAttachmentDefinition */
type NetAttachController struct {
	clientset *netdefclient.Clientset
}

/* Creates an instance of our Controller */
func NewNetAttachController() (*NetAttachController, error) {
	/* Getting Cluster Config */
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	/* Kubernetes Client */
	clientset, err := netdefclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &NetAttachController{clientset: clientset}, nil
}

/* Controller Runner */
func (c *NetAttachController) Run(stopCh <-chan struct{}) error {

	/* Creating a NetworkAttachmentDefinition Informer */
	netDefInformer := cache.NewSharedInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return c.clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions("").List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return c.clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions("").Watch(context.TODO(), options)
			},
		},
		&netdefv1.NetworkAttachmentDefinition{}, 0*time.Second)

	/* Adding NetworkAttachmentDefinition Handlers to Add, Update and Delete */
	_, err := netDefInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			nDef := obj.(*netdefv1.NetworkAttachmentDefinition)
			if handler.AddNetAttach(nDef) {
				ForceReconcile()
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldDef := oldObj.(*netdefv1.NetworkAttachmentDefinition)
			_ = oldDef
			newDef := newObj.(*netdefv1.NetworkAttachmentDefinition)
			if handler.UpdateNetAttach(newDef) {
				ForceReconcile()
			}
		},
		DeleteFunc: func(obj interface{}) {
			nDef := obj.(*netdefv1.NetworkAttachmentDefinition)
			if handler.DeleteNetAttach(nDef) {
				ForceReconcile()
			}
		},
	})

	if err != nil {
		klog.Errorf("Error adding NetworkAttachmentDefinition handlers:: %v\n", err)
		return err
	}

	/* Start NetworkAttachmentDefinition Informer */
	go netDefInformer.Run(stopCh)

	/* Waiting for sync */
	if !cache.WaitForCacheSync(stopCh, netDefInformer.HasSynced) {
		klog.Errorf("failed to sync informers")
		return nil
	}

	return nil
}
