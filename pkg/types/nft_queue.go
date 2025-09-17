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

import (
	"github.com/google/nftables"
)

/* NftOperationType defines the types of nftables operations that can be queued. */
type NftOperationType string

// Constantes para NftOperationType
const (
	OpUnknown    NftOperationType = "Unknown"
	OpAddTable   NftOperationType = "AddTable"
	OpDelTable   NftOperationType = "DelTable"
	OpAddChain   NftOperationType = "AddChain"
	OpFlushChain NftOperationType = "FlushChain"
	OpDelChain   NftOperationType = "DelChain"
	OpAddSet     NftOperationType = "AddSet"
	OpDelSet     NftOperationType = "DelSet"
	OpAddRule    NftOperationType = "AddRule"
	OpDelRule    NftOperationType = "DelRule"
	OpFlushSet   NftOperationType = "FlushSet"
)

/* QueuedNftOperation stores the details of a pending nftables operation. */
type QueuedNftOperation struct {
	Type        NftOperationType
	Table       *nftables.Table       /* Required for most ops, points to the relevant Table object  */
	Chain       *nftables.Chain       /* For chain and rule ops, points to the relevant Chain object */
	Set         *nftables.Set         /* For set ops, points to the relevant Set object              */
	Rule        *nftables.Rule        /* For rule ops (AddRule, DelRule)                             */
	SetElements []nftables.SetElement /* Only for OpAddSet                                           */
	Description string                /* Logging-friendly description                                */
}
