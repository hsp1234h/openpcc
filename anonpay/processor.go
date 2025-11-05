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

package anonpay

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/otel/otelutil"
)

// Processor represents the service that accepts and processes anonymous credits as payment.
//
// Processing starts with a call to [BeginTransaction], which returns a [Transaction].
// This Transaction can either be comitted by calling [Transaction.Commit] or rolled
// back by calling [Transaction.Rollback].
//
// When committing a transaction the amount of unspend credits is provided, which will
// return a (potentially zero-valued) coupon that can be exchanged at the bank for a
// new anonymous credit of equivalent value by the user.
//
// When a transaction is rolled back, the anonymous credit provided by the user can be
// re-used.
type Processor struct {
	nonceLocker NonceLocker
	issuer      *Issuer
}

func NewProcessor(issuer *Issuer, nonceLocker NonceLocker) *Processor {
	return &Processor{
		issuer:      issuer,
		nonceLocker: nonceLocker,
	}
}

func (t *Processor) BeginTransaction(ctx context.Context, cred *BlindedCredit) (*Transaction, error) {
	_, span := otelutil.Tracer.Start(ctx, "anonpay.Processor.BeginTransaction")
	defer span.End()

	err := t.issuer.VerifyCredit(ctx, cred)
	if err != nil {
		return nil, InputError{
			Err: fmt.Errorf("failed to verify credit: %w", err),
		}
	}

	lockedNonce, err := t.nonceLocker.CheckAndLockNonce(ctx, cred.Nonce())
	if err != nil {
		return nil, fmt.Errorf("failed to lock nonce: %w", err)
	}

	ctx, cancelCauseFunc := context.WithCancelCause(ctx)

	tx := &Transaction{
		mu:          &sync.Mutex{},
		ctx:         ctx,
		cancelFunc:  cancelCauseFunc,
		issuer:      t.issuer,
		lockedNonce: lockedNonce,
		credit:      cred,
	}

	return tx, nil
}

var ErrFinished = errors.New("transaction has finished")

type Transaction struct {
	mu          *sync.Mutex
	ctx         context.Context
	cancelFunc  context.CancelCauseFunc
	issuer      *Issuer
	lockedNonce LockedNonce
	credit      *BlindedCredit
}

func (tx *Transaction) Context() context.Context {
	return tx.ctx
}

func (tx *Transaction) Credit() *BlindedCredit {
	return tx.credit
}

// Commit closes the transaction and considers the incoming credit fully spend.
func (tx *Transaction) Commit() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	var err error
	if tx.ctx.Err() != nil {
		return tx.ctx.Err()
	}
	defer func() {
		if err != nil {
			tx.cancelFunc(err)
		} else {
			tx.cancelFunc(ErrFinished)
		}
	}()

	err = tx.lockedNonce.Consume(tx.ctx)
	if err != nil {
		err = errors.Join(err, tx.lockedNonce.Release(tx.ctx))
		return fmt.Errorf("failed to consume locked nonce: %w", err)
	}

	return nil
}

func (tx *Transaction) CommitWithUnspend(unspend currency.Value) (*UnblindedCredit, error) {
	err := tx.Commit()
	if err != nil {
		return nil, err
	}

	cred, err := tx.issuer.IssueUnblindedCredit(tx.ctx, unspend)
	if err != nil {
		return nil, fmt.Errorf("failed to create refund credit: %w", err)
	}

	return cred, nil
}

// Rollback rolls back the transaction, it's safe to call in a defer because it won't return
// an error even if the transaction has already been finished.
func (tx *Transaction) Rollback() error {
	if tx.ctx.Err() != nil {
		if errors.Is(context.Cause(tx.ctx), ErrFinished) {
			return nil
		}

		return tx.ctx.Err()
	}

	err := tx.lockedNonce.Release(tx.ctx)
	if err != nil {
		return fmt.Errorf("failed to release locked nonce: %w", err)
	}
	return nil
}
