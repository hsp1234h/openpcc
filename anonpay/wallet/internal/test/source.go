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

package test

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
)

type Source struct {
	WithdrawFunc func(ctx context.Context, transferID []byte, amount currency.Value) (*anonpay.BlindedCredit, error)
	DepositFunc  func(ctx context.Context, transferID []byte, credits ...*anonpay.BlindedCredit) error

	t              *testing.T
	mu             *sync.Mutex
	account        *account
	initialBalance int64
}

func NewSource(t *testing.T, balance int64) *Source {
	return &Source{
		t:  t,
		mu: &sync.Mutex{},
		account: &account{
			balance:   balance,
			mutations: []int64{},
		},
		initialBalance: balance,
	}
}

func (s *Source) Withdraw(ctx context.Context, transferID []byte, amount currency.Value) (*anonpay.BlindedCredit, error) {
	if s.WithdrawFunc != nil {
		return s.WithdrawFunc(ctx, transferID, amount)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	credits, err := s.account.withdraw(s.t, 1, amount)
	if err != nil {
		return nil, err
	}
	return credits[0], nil
}

func (s *Source) Deposit(ctx context.Context, transferID []byte, credits ...*anonpay.BlindedCredit) error {
	if s.DepositFunc != nil {
		return s.DepositFunc(ctx, transferID, credits...)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.account.deposit(credits...)
}

func (s *Source) TestState() (int64, []int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.account.balance, slices.Clone(s.account.mutations)
}

func (s *Source) TestInitialBalance() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initialBalance
}
