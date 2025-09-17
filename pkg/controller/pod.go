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

/* Controller to handle Pods */
type PodController struct {
	clientset *kubernetes.Clientset
}

/* Creates an instance of our Controller */
func NewPodController() (*PodController, error) {
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

	return &PodController{clientset: clientset}, nil
}

/* Controller Runner */
func (c *PodController) Run(stopCh <-chan struct{}) error {

	/* Creating a Pod Informer */
	podInformer := cache.NewSharedInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return c.clientset.CoreV1().Pods("").List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return c.clientset.CoreV1().Pods("").Watch(context.TODO(), options)
			},
		},
		&v1.Pod{}, 0*time.Second)

	/* Adding Pod Handlers to Add, Update and Delete */
	_, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			if handler.AddPod(pod) {
				ForceReconcile()
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod := oldObj.(*v1.Pod)
			_ = oldPod
			newPod := newObj.(*v1.Pod)
			if handler.UpdatePod(newPod) {
				ForceReconcile()
			}
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			if handler.DeletePod(pod) {
				ForceReconcile()
			}
		},
	})

	if err != nil {
		klog.Errorf("Error adding Pod handlers: %v\n", err)
		return err
	}

	/* Start Pod Informer */
	go podInformer.Run(stopCh)

	/* Waiting for sync */
	if !cache.WaitForCacheSync(stopCh, podInformer.HasSynced) {
		klog.Errorf("failed to sync pod informer")
		return nil
	}

	return nil
}
