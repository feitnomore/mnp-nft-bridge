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
package types

/* PodChainMetadata stores the necessary information to reconstruct
 * the context of a pod-specific nftables chain.
 * PodChainMetadata stores the necessary information to reconstruct
 * the context of a pod-specific nftables chain.
 */
type PodChainMetadata struct {
	PolicyName             string
	PolicyNamespace        string
	PodName                string
	PodNamespace           string
	PodMac                 string
	ChainType              string /* IngressChainType or EgressChainType                                                         */
	FullChainName          string /* e.g., KUBE_MULTI_INGRESS_hashsuffix or KUBE_MULTI_INGRESS_ISOLATION_hashsuffix              */
	ChainSuffix            string /* The hash part, e.g., abcdef123                                                              */
	PolicyRuleCount        int    /* Number of ingress or egress rules in the policy for this ChainType. 0 for isolation chains. */
	IsIsolationChain       bool   /* True if this chain is solely for isolation (contains only a drop rule).                     */
	PolicyIngressRuleCount int
	PolicyEgressRuleCount  int
}
