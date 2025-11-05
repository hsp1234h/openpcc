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

package transfer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/banking"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/delay"
)

// BlindBank adapts the banking.BlindBankContract to the transfer.BlindBank interface.
type BlindBank struct {
	payee *anonpay.Payee
	bank  banking.BlindBankContract
}

func NewBlindBank(payee *anonpay.Payee, bank banking.BlindBankContract) *BlindBank {
	return &BlindBank{
		payee: payee,
		bank:  bank,
	}
}

func (b *BlindBank) WithdrawBatch(ctx context.Context, transferID []byte, account banking.AccountToken, credits int, amount currency.Value) (int64, []*anonpay.BlindedCredit, error) {
	if credits <= 0 {
		return 0, nil, errors.New("cant' withdraw < 1 credits")
	}

	state := make([]anonpay.BlindSignState, 0, credits)
	reqs := make([]anonpay.BlindSignRequest, 0, credits)
	for range credits {
		s, err := b.payee.BeginBlindedCredit(ctx, amount)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to prepare new credit: %w", err)
		}

		state = append(state, *s)
		reqs = append(reqs, s.Request())
	}

	newBalance, blindSignatures, err := b.bank.WithdrawBatch(ctx, transferID, account, reqs)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to withdraw batch: %w", err)
	}

	if len(blindSignatures) != len(state) {
		return 0, nil, fmt.Errorf("bank returned an invalid amount of blind signatures, wanted %d, got %d", credits, len(blindSignatures))
	}

	withdrawnCredits := make([]*anonpay.BlindedCredit, 0, credits)
	for i, unsignedCredit := range state {
		cred, err := unsignedCredit.Finalize(blindSignatures[i])
		if err != nil {
			return 0, nil, fmt.Errorf("failed to finalize credit: %w", err)
		}

		withdrawnCredits = append(withdrawnCredits, cred)
	}

	return newBalance, withdrawnCredits, nil
}

func (b *BlindBank) WithdrawFullUnblinded(ctx context.Context, transferID []byte, account banking.AccountToken) (*anonpay.UnblindedCredit, error) {
	return b.bank.WithdrawFullUnblinded(ctx, transferID, account)
}

func (b *BlindBank) Deposit(ctx context.Context, transferID []byte, accountID banking.AccountToken, credits ...*anonpay.BlindedCredit) (int64, error) {
	// TODO: Bit of a hack, we need a batch deposit endpoint.
	if len(credits) == 0 {
		return 0, errors.New("can't deposit 0 credits")
	}

	var (
		lastBalance int64
		err         error
	)
	for _, cred := range credits {
		lastBalance, err = b.bank.Deposit(ctx, transferID, accountID, cred)
		if err != nil {
			return lastBalance, err
		}
	}

	return lastBalance, nil
}

func (b *BlindBank) Exchange(ctx context.Context, transferID []byte, credit anonpay.AnyCredit) (*anonpay.BlindedCredit, error) {
	s, err := b.payee.BeginBlindedCredit(ctx, credit.Value())
	if err != nil {
		return nil, fmt.Errorf("failed to prepare new credit: %w", err)
	}

	blindSignature, err := b.bank.Exchange(ctx, transferID, credit, s.Request())
	if err != nil {
		return nil, fmt.Errorf("failed to exchange credit: %w", err)
	}

	exchangedCredit, err := s.Finalize(blindSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize credit: %w", err)
	}

	return exchangedCredit, nil
}

func (b *BlindBank) Balance(ctx context.Context, account banking.AccountToken) (int64, error) {
	return b.bank.Balance(ctx, account)
}

// Account is the local reference of a bank account in the blind bank.
//
// Transfers made to/from such an account will call the blind bank as appropriate.
type Account struct {
	mu      *sync.Mutex
	bank    *BlindBank
	token   banking.AccountToken
	balance int64
	delay   time.Duration
}

func EmptyBankAccount(ctx context.Context, b *BlindBank, maxDelay time.Duration) (*Account, error) {
	token, err := banking.GenerateAccountToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate account token: %w", err)
	}

	return &Account{
		mu:      &sync.Mutex{},
		bank:    b,
		token:   token,
		balance: 0,
		delay:   maxDelay,
	}, nil
}

// RestoreBankAccount restores an existing bank account.
func RestoreBankAccount(_ context.Context, b *BlindBank, account banking.AccountToken, balance int64, maxDelay time.Duration) (*Account, error) {
	if balance < 0 {
		return nil, fmt.Errorf("negative balance: %d", balance)
	}
	return &Account{
		mu:      &sync.Mutex{},
		bank:    b,
		token:   account,
		balance: balance,
		delay:   maxDelay,
	}, nil
}

func (a *Account) Token() banking.AccountToken {
	return a.token
}

func (a *Account) Balance() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.balance
}

func (a *Account) maxDelay() time.Duration {
	return a.delay
}

func (*Account) origin() creditOrigin {
	return blindbankOrigin
}

func (*Account) allowedOrigins() []creditOrigin {
	// Credits from all origins can be deposited in accounts in the blind bank.
	return []creditOrigin{
		sourceOrigin,
		blindbankOrigin,
		userOrigin,
	}
}

func (a *Account) withdraw(ctx context.Context, transferID []byte, w Withdrawal) ([]*anonpay.BlindedCredit, int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if w == FullWithdrawal {
		unblindedCredit, err := a.bank.WithdrawFullUnblinded(ctx, transferID, a.token)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to withdraw full account: %w", err)
		}

		// TODO: Refactor anonpay/banking to explicitly model unblinded credits as a different concept.
		// we can then model this two-operation properly as a transfer in the pipeline.
		_, err = delay.UpTo(ctx, a.maxDelay())
		if err != nil {
			return nil, 0, fmt.Errorf("failed to delay exchange operation: %w", err)
		}

		credit, err := a.bank.Exchange(ctx, []byte{}, unblindedCredit)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to exchange unblinded withdrawal: %w", err)
		}

		roundingGain := credit.Value().AmountOrZero() - a.balance
		a.balance = 0
		return []*anonpay.BlindedCredit{credit}, roundingGain, nil
	}

	expectNewBalance := a.balance - int64(w.Credits)*w.Amount.AmountOrZero()
	if expectNewBalance < 0 {
		return nil, 0, WithdrawalError{
			Withdrawal: w,
			Err: anonpay.InsufficientBalanceError{
				Balance: a.balance,
			},
		}
	}

	newBalance, credits, err := a.bank.WithdrawBatch(ctx, transferID, a.token, w.Credits, w.Amount)
	if err != nil {
		return nil, 0, err
	}
	a.balance = newBalance
	if newBalance != expectNewBalance {
		slog.Error("unexpected new balance for bank account", "expected_balance", expectNewBalance, "balance", newBalance)
	}

	return credits, 0, nil
}

func (a *Account) deposit(ctx context.Context, transferID []byte, credits ...*anonpay.BlindedCredit) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	newBalance, err := a.bank.Deposit(ctx, transferID, a.token, credits...)
	if err != nil {
		return err
	}
	a.balance = newBalance
	return nil
}
