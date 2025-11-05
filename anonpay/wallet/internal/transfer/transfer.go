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
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/delay"
	"github.com/openpcc/openpcc/otel/otelutil"
)

type creditOrigin string

const (
	sourceOrigin    = creditOrigin("source")
	blindbankOrigin = creditOrigin("blind bank")
	userOrigin      = creditOrigin("user")
)

type Withdrawal struct {
	full    bool
	Credits int
	Amount  currency.Value

	// Optimistic withdrawals are made without any expectations that the funds
	// are actually available in the Withdrawable. They are allowed to fail
	// due to [InsufficientBalanceError] or [NoMatchingCreditsError].
	Optimistic bool
}

func (w Withdrawal) String() string {
	if w.full {
		return "full"
	}
	return fmt.Sprintf("%dx%d (%d)", w.Credits, w.Amount.AmountOrZero(), int64(w.Credits)*w.Amount.AmountOrZero())
}

// FullWithdrawal is a special Withdrawal used to indicate that a withdrawal should withdraw
// all credits available to a withdrawable. Not every withdrawable supports this. Depending on
// the withdrawable a full withdrawal might return one large credit or multiple smaller credits.
//
// If multiple credits are returned they should all be of the same amount.
var FullWithdrawal = Withdrawal{
	full: true,
}

// Withdrawable can have credits withdrawn from it.
type Withdrawable interface {
	origin() creditOrigin
	maxDelay() time.Duration
	withdraw(ctx context.Context, transferID []byte, w Withdrawal) ([]*anonpay.BlindedCredit, int64, error)
}

// Depositable can have credits deposited in it.
type Depositable interface {
	allowedOrigins() []creditOrigin
	maxDelay() time.Duration
	// when multiple credits are deposited, they should all be of the same amount.
	deposit(ctx context.Context, transferID []byte, credits ...*anonpay.BlindedCredit) error
}

// Intent represents the intention of transferring a number of credits from
// Withdrawable to Depositable. A Intent can be processed by calling [Process].
type Intent[W Withdrawable, D Depositable] struct {
	Withdrawal Withdrawal
	// From is the Withdrawable from which credits will be withdrawn.
	From W
	// To is the Depositable into which the credits will be deposited.
	To D
}

func (i *Intent[W, D]) IsExpectedError(err error) bool {
	if !i.Withdrawal.Optimistic {
		return false
	}

	// allowed errors
	var noMatchingCreds anonpay.CreditsNotAvailableError
	var insufficientBalanceError anonpay.InsufficientBalanceError
	return errors.As(err, &noMatchingCreds) || errors.As(err, &insufficientBalanceError)
}

func EstimateAvgDuration(maxDelay, avgWithdraw, avgDeposit time.Duration) time.Duration {
	return maxDelay/2 + avgWithdraw + maxDelay/2 + avgDeposit
}

func GenerateID() ([]byte, error) {
	id := make([]byte, 32)
	_, err := rand.Read(id)
	if err != nil {
		return nil, fmt.Errorf("failed to generate id: %w", err)
	}
	return id, nil
}

// Transfer is a successful transfer of credits from a Withdrawable to a Depositable.
type Transfer[W Withdrawable, D Depositable] struct {
	id           []byte
	intent       *Intent[W, D]
	roundingGain int64
	amounts      []currency.Value
}

// Process processes an intent and attempts to execute a transfer.
func Process[W Withdrawable, D Depositable](ctx context.Context, intent *Intent[W, D], logger IntentLogger[W, D]) (*Transfer[W, D], error) {
	ctx, span := otelutil.Tracer.Start(ctx, "wallet.transfer.Process")
	defer span.End()

	allowedOrigins := intent.To.allowedOrigins()
	origin := intent.From.origin()
	if !slices.Contains(allowedOrigins, origin) {
		return nil, fmt.Errorf("%v is not an allowed origin for deposit target allowed (%v)", origin, allowedOrigins)
	}

	id, err := GenerateID()
	if err != nil {
		return nil, err
	}

	_, err = delay.UpTo(ctx, intent.From.maxDelay())
	if err != nil {
		return nil, fmt.Errorf("failed to delay before withdraw: %w", err)
	}

	progressLogger, err := logger.LogIntent(ctx, id, intent)
	if err != nil {
		return nil, fmt.Errorf("failed to log intent: %w", err)
	}

	withdrawCtx, withdrawSpan := otelutil.Tracer.Start(ctx, "wallet.transfer.Process.withdraw")
	withdrew, roundingGain, err := intent.From.withdraw(withdrawCtx, id, intent.Withdrawal)
	withdrawSpan.End()
	if err != nil {
		if intent.IsExpectedError(err) {
			logErr := progressLogger.LogFinishErrorOK(err)
			if logErr != nil {
				// return just the log error as we now need to do a hard exit.
				// if we were to return the expected error, it might get masked
				// by the unexpected log error.
				return nil, logErr
			}
			return nil, err
		}

		err = fmt.Errorf("failed to withdraw: %w", err)
		err = errors.Join(err, progressLogger.LogFinishUnexpectedError(err))
		return nil, err
	}

	amounts := make([]currency.Value, 0, len(withdrew))
	for i, cred := range withdrew {
		if i > 0 {
			prev := withdrew[i-1].Value().AmountOrZero()
			current := cred.Value().AmountOrZero()
			if prev != current {
				err = fmt.Errorf(
					"multiple withdrawn credits are expected to have the same value, but got %d and %d", prev, current,
				)
				err = errors.Join(err, progressLogger.LogFinishUnexpectedError(err))
				return nil, err
			}
		}
		amounts = append(amounts, cred.Value())
	}

	err = progressLogger.LogWithdrawOK(roundingGain, withdrew)
	if err != nil {
		return nil, fmt.Errorf("failed to log withdrawal: %w", err)
	}

	betweenDelay := max(intent.From.maxDelay(), intent.To.maxDelay())
	_, err = delay.UpTo(ctx, betweenDelay)
	if err != nil {
		err = errors.Join(err, progressLogger.LogFinishUnexpectedError(err))
		return nil, fmt.Errorf("failed to delay after withdraw: %w", err)
	}

	depCtx, depSpan := otelutil.Tracer.Start(ctx, "wallet.transfer.Process.deposit")
	err = intent.To.deposit(depCtx, id, withdrew...)
	depSpan.End()
	if err != nil {
		err = errors.Join(err, progressLogger.LogFinishUnexpectedError(err))
		return nil, fmt.Errorf("failed to withdraw: %w", err)
	}

	err = progressLogger.LogFinishDepositOK()
	if err != nil {
		return nil, fmt.Errorf("failed to log deposit: %w", err)
	}

	return &Transfer[W, D]{
		id:           id,
		intent:       intent,
		roundingGain: roundingGain,
		amounts:      amounts,
	}, nil
}

func (t *Transfer[W, D]) ID() []byte {
	return t.id
}

func (t *Transfer[W, D]) From() W {
	return t.intent.From
}

func (t *Transfer[W, D]) To() D {
	return t.intent.To
}

// RoundingGain is the amount that was gained (or lost) by the withdrawal in this transfer.
//
// Some of the withdrawal operations round the results for anonimity reasons (see the currency package)
// for more details. This field collects the rounding information.
func (t *Transfer[W, D]) RoundingGain() int64 {
	return t.roundingGain
}

func (t *Transfer[W, D]) Amounts() []currency.Value {
	return t.amounts
}

// RepWithdrawable is a helper type used to indicate a withdrawable has been
// repeated several times. A pipeline step can then use [RepResults] to check
// when the repeated results are complete.
type RepWithdrawable[W Withdrawable] struct {
	W     W
	Index int
	Last  bool
}

func (rw RepWithdrawable[W]) origin() creditOrigin {
	return rw.W.origin()
}

func (rw RepWithdrawable[W]) maxDelay() time.Duration {
	return rw.W.maxDelay()
}

func (rw RepWithdrawable[W]) withdraw(ctx context.Context, transferID []byte, w Withdrawal) ([]*anonpay.BlindedCredit, int64, error) {
	return rw.W.withdraw(ctx, transferID, w)
}

func (rw RepWithdrawable[W]) RepeatedResult() (int, bool) {
	return rw.Index, rw.Last
}

// RepDepositable is a helper type used to indicate a depositable has been
// repeated several times. A pipeline step can then use [RepResults] to check
// when the received results are complete.
type RepDepositable[D Depositable] struct {
	D     D
	Index int
	Last  bool
}

func (rd RepDepositable[D]) allowedOrigins() []creditOrigin {
	return rd.D.allowedOrigins()
}

func (rd RepDepositable[D]) maxDelay() time.Duration {
	return rd.D.maxDelay()
}

func (rd RepDepositable[D]) deposit(ctx context.Context, transferID []byte, credits ...*anonpay.BlindedCredit) error {
	return rd.D.deposit(ctx, transferID, credits...)
}

func (rd RepDepositable[D]) RepeatedResult() (int, bool) {
	return rd.Index, rd.Last
}

// RepResults tracks repeated results and indicates when they are complete.
type RepResults struct {
	seen     map[int]struct{}
	groupLen *int
}

type RepResult interface {
	RepeatedResult() (int, bool)
}

func (g *RepResults) Add(i RepResult) {
	idx, last := i.RepeatedResult()
	if g.seen == nil {
		g.seen = map[int]struct{}{}
	}
	g.seen[idx] = struct{}{}
	if last {
		groupLen := idx + 1
		g.groupLen = &groupLen
	}
}

// Complete indicates whether all results in a group have been received.
func (g *RepResults) Complete() bool {
	if g.groupLen == nil {
		return false
	}

	return len(g.seen) == *g.groupLen
}
