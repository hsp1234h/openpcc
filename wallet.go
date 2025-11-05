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

package openpcc

import (
	"context"

	"github.com/openpcc/openpcc/anonpay/wallet"
)

type Wallet interface {
	BeginPayment(ctx context.Context, amount int64) (wallet.Payment, error)
	Status() wallet.Status
	SetDefaultCreditAmount(amount int64) error
	Close(ctx context.Context) error
}
