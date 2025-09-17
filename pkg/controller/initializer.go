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
	"github.com/feitnomore/mnp-nft-bridge/pkg/cache"
	"github.com/feitnomore/mnp-nft-bridge/pkg/types"
	"k8s.io/klog/v2"
)

/* This is our main controller */
type Controllers struct {
	podController                         PodController
	namespaceController                   NamespaceController
	multiNetworkPolicyController          MultiNetworkPolicyController
	networkAttachmentDefinitionController NetAttachController
}

/* Creating instances of our aux controllers */
func NewControllers(nft *types.NFTables) (*Controllers, error) {

	/* Initializing Caches */
	cache.InitializePodCache()
	cache.InitializeNamespaceCache()
	cache.InitializeMultiNetworkPolicyCache()
	cache.InitializeNetworkAttachmentDefinitionCache()
	cache.InitializeNftablesCache()
	cache.InitializeNftPodChainMetadataCache()

	/* Loading nftables chains, tables and rules */
	klog.V(8).Infof("Loading NFT data... \n")
	nft.LoadEverything()

	/* Creating NFTables Reconciler */
	NewNftablesController(nft)

	/* creating Pod Controller */
	klog.V(8).Infof("creating Pod Controller... \n")
	podCtrl, err := NewPodController()
	if err != nil {
		klog.Errorf("Error creating Pod Controller: %v \n", err)
		return nil, err
	}

	/* creating Namespace Controller */
	klog.V(8).Infof("creating Kubernetes Controller... \n")
	namespaceCtrl, err := NewNamespaceController()
	if err != nil {
		klog.Errorf("Error creating Namespace Controller: %v \n", err)
		return nil, err
	}

	/* creating MultiNetworkPolicy Controller */
	klog.V(8).Infof("creating MultiNetworkPolicy Controller... \n")
	mnpCtrl, err := NewMultiNetworkPolicyController()
	if err != nil {
		klog.Errorf("Error creating MultiNetworkPolicy Controller: %v \n", err)
		return nil, err
	}

	/* creating NetworkAttachmentDefinition Controller */
	klog.V(8).Infof("creating NetworkAttachmentDefinition Controller... \n")
	nadCtrl, err := NewNetAttachController()
	if err != nil {
		klog.Errorf("Error creating NetworkAttachmentDefinition Controller: %v \n", err)
		return nil, err
	}

	return &Controllers{podController: *podCtrl, namespaceController: *namespaceCtrl, multiNetworkPolicyController: *mnpCtrl, networkAttachmentDefinitionController: *nadCtrl}, nil
}

func (c *Controllers) Run(stopCh <-chan struct{}) error {

	klog.Infof("Starting controllers... \n")

	klog.V(8).Infof("Starting c.nftablesController.StartController()... \n")
	StartNftController()

	klog.V(8).Infof("Starting c.podController.Run()... \n")
	podctrl := c.podController.Run(stopCh)
	if podctrl != nil {
		klog.Errorf("Error starting Kubernetes Controller: %v \n", podctrl)
		return podctrl
	}
	klog.V(8).Infof("Starting c.namespaceController.Run()... \n")
	namespacectrl := c.namespaceController.Run(stopCh)
	if namespacectrl != nil {
		klog.Errorf("Error starting Kubernetes Controller: %v \n", namespacectrl)
		return namespacectrl
	}
	klog.V(8).Infof("Starting c.multiNetworkPolicyController.Run()... \n")
	multinetctrl := c.multiNetworkPolicyController.Run(stopCh)
	if multinetctrl != nil {
		klog.Errorf("Error starting MultiNetworkPolicy Controller: %v \n", multinetctrl)
		return multinetctrl
	}
	klog.V(8).Infof("Starting c.networkAttachmentDefinitionController.Run()... \n")
	netdefctrl := c.networkAttachmentDefinitionController.Run(stopCh)
	if netdefctrl != nil {
		klog.Errorf("Error starting NetworkAttachmentDefinition Controller: %v \n", netdefctrl)
		return netdefctrl
	}

	return nil
}
