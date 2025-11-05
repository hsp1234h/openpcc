// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

const (
	RoutingInfoHeader = "X-Routing-Info"
	// NodeIDHeader is set in the response to identify the candidate node that is handling the request.
	NodeIDHeader = "X-Node-ID"

	// CreditHeader should contain a base64-encoded binary-serialized protobuf containing a credit as received from the upstream client.
	CreditHeader = "X-Credit"

	// CreditAmountHeader should contain an integer representing an amount of credit as forwarded to the downstream server.
	CreditAmountHeader = "X-Credit-Amount"

	// RefundHeader should contain a base64-encoded binary-serialized protobuf containing a credit as returned to the upstream client.
	RefundHeader = "X-Refund"

	// RefundAmountHeader should contain a base64-encoded binary-serialized protobuf containing a currency value as received from the downstream server.
	RefundAmountHeader = "X-Refund-Amount"
)
