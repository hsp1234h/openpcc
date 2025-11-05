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
	"testing"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/anonpay/wallet"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type FakeWallet struct {
	BeginPaymentFunc           func(ctx context.Context, amount int64) (wallet.Payment, error)
	SetDefaultCreditAmountFunc func(limit int64) error
	CloseCalls                 int
}

func (w *FakeWallet) BeginPayment(ctx context.Context, amount int64) (wallet.Payment, error) {
	if w.BeginPaymentFunc != nil {
		return w.BeginPaymentFunc(ctx, amount)
	}

	return nil, assert.AnError
}

func (*FakeWallet) Status() wallet.Status {
	return wallet.Status{}
}

func (w *FakeWallet) SetDefaultCreditAmount(limit int64) error {
	if w.SetDefaultCreditAmountFunc != nil {
		return w.SetDefaultCreditAmountFunc(limit)
	}
	return nil
}

func (w *FakeWallet) Close(_ context.Context) error {
	w.CloseCalls++
	return nil
}

type FakePayment struct {
	credit       *anonpay.BlindedCredit
	successCalls int
	cancelCalls  int
	gotUnspend   *anonpay.UnblindedCredit
}

func NewFakePayment(t *testing.T, amount int64) *FakePayment {
	val, err := currency.Rounded(float64(amount), 1)
	require.NoError(t, err)
	return &FakePayment{
		credit: anonpaytest.MustBlindCredit(t.Context(), val),
	}
}

func (p *FakePayment) Credit() *anonpay.BlindedCredit {
	return p.credit
}

func (p *FakePayment) Success(unspend *anonpay.UnblindedCredit) error {
	p.successCalls++
	p.gotUnspend = unspend
	return nil
}

func (p *FakePayment) Cancel() error {
	p.cancelCalls++
	return nil
}

func (p *FakePayment) TestVerifySuccess(t *testing.T, unspend *anonpay.UnblindedCredit) {
	t.Helper()
	// verify payment succeeded
	require.Equal(t, 1, p.successCalls)
	require.Equal(t, 0, p.cancelCalls)
	require.Equal(t, unspend, p.gotUnspend)
}

func (p *FakePayment) TestVerifyCancel(t *testing.T) {
	t.Helper()

	require.Equal(t, 1, p.cancelCalls)
	require.Nil(t, p.gotUnspend)
}

func (p *FakePayment) TestUnspendCredit() *anonpay.UnblindedCredit {
	return p.gotUnspend
}
