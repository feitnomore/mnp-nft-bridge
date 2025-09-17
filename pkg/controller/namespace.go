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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

/* Controller to handle Namespaces */
type NamespaceController struct {
	clientset *kubernetes.Clientset
}

/* Creates an instance of our Controller */
func NewNamespaceController() (*NamespaceController, error) {
	/* Getting Cluster Config */
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	/* Kubernetes Client */
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &NamespaceController{clientset: clientset}, nil
}

/* Controller Runner */
func (c *NamespaceController) Run(stopCh <-chan struct{}) error {

	/* Creating a Namespace Informer */
	namespaceInformer := cache.NewSharedInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return c.clientset.CoreV1().Namespaces().List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return c.clientset.CoreV1().Namespaces().Watch(context.TODO(), options)
			},
		},
		&v1.Namespace{}, 0*time.Second)

	/* Adding Namespace Handlers to Add, Update and Delete */
	_, err := namespaceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			nsd := obj.(*v1.Namespace)
			if handler.AddNamespace(nsd) {
				ForceReconcile()
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldNs := oldObj.(*v1.Namespace)
			_ = oldNs
			newNs := newObj.(*v1.Namespace)
			if handler.UpdateNamespace(newNs) {
				ForceReconcile()
			}
		},
		DeleteFunc: func(obj interface{}) {
			nsd := obj.(*v1.Namespace)
			if handler.DeleteNamespace(nsd) {
				ForceReconcile()
			}
		},
	})

	if err != nil {
		klog.Errorf("Error adding Namespace handlers: %v\n", err)
		return err
	}

	/* Start Namespace Informer */
	go namespaceInformer.Run(stopCh)

	/* Waiting for sync */
	if !cache.WaitForCacheSync(stopCh, namespaceInformer.HasSynced) {
		klog.Errorf("failed to sync namespace informer")
		return nil
	}

	return nil
}
