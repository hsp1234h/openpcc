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

// ahttp contains the attested http functionality. It encapsulates requests and responses
// so that they can be handled by a confidential compute node.
package ahttp

import "github.com/openpcc/openpcc/anonpay/currency"

// CreditHeader should contain a base64-encoded binary-serialized protobuf containing an anonpay blinded credit.
const CreditHeader = "X-Credit"

// RefundHeader should contain a base64-encoded binary-serialized protobuf containing an anonpay unblinded credit.
const RefundHeader = "X-Refund"

// NodeCreditAmountHeader should contain an integer representing an amount of credit. The node should use this
// header to retrieve the amount of credit.
const NodeCreditAmountHeader = "X-Credit-Amount"

// NodeRefundAmountHeader should contain an integer representing the amount of credit that should be refunded.
const NodeRefundAmountHeader = "X-Refund-Amount"

// An AttestationCurrencyValue is a special Currency value used to create credits that pay for manifests request.
var AttestationCurrencyValue = currency.MustSpecial(0)
