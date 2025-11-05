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

package wallet

import (
	"context"
	"fmt"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
)

type Wallet1AuthClient interface {
	GetCredit(ctx context.Context, amount int64) (*anonpay.BlindedCredit, error)
	PutCredit(ctx context.Context, credit *anonpay.BlindedCredit) error
}

// Wallet1SourceService uses an wallet1 auth client to fetch credits from source.
type Wallet1SourceService struct {
	client Wallet1AuthClient
}

func NewWallet1SourceService(client Wallet1AuthClient) *Wallet1SourceService {
	return &Wallet1SourceService{
		client: client,
	}
}

func (s *Wallet1SourceService) Withdraw(ctx context.Context, _ []byte, amount currency.Value) (*anonpay.BlindedCredit, error) {
	credit, err := s.client.GetCredit(ctx, amount.AmountOrZero())
	if err != nil {
		return nil, fmt.Errorf("failed to get credit: %w", err)
	}
	return credit, nil
}

func (s *Wallet1SourceService) Deposit(ctx context.Context, _ []byte, credits ...*anonpay.BlindedCredit) error {
	for i, credit := range credits {
		err := s.client.PutCredit(ctx, credit)
		if err != nil {
			return fmt.Errorf("failed to put credit %d: %w", i, err)
		}
	}
	return nil
}
