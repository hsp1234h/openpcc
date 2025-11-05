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

package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/stats"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/transfer"
	"github.com/openpcc/openpcc/work"
)

type PrefetchWithdrawStats struct {
	SplitAccounts   *stats.TransferCounter
	PaymentRequests *stats.TransferCounter
}

func NewPrefetchWithdrawStats() *PrefetchWithdrawStats {
	return &PrefetchWithdrawStats{
		SplitAccounts:   stats.NewTransferCounter(),
		PaymentRequests: stats.NewTransferCounter(),
	}
}

type PrefetchWithdrawSteps struct {
	ID                             string
	Stats                          *PrefetchWithdrawStats
	MaxExpiryDuration              time.Duration
	WorkPool                       *work.Pool
	BankBatchFunc                  BankBatchFunc
	MaxParallelBankBatches         int
	PrefetchAmount                 currency.Value
	InputRequests                  <-chan *transfer.PaymentRequest
	InputAccounts                  <-chan *transfer.Account
	OutputBankBatchesToConsolidate *work.Channel[*transfer.BankBatch]
	OutputAccountsToConsolidate    *work.Channel[*transfer.Account]
}

func NewPrefetchWithdrawSteps(s *PrefetchWithdrawSteps) []work.PipelineStep {
	// verify dev provided inputs to aid with debugging.
	work.MustHaveInput(s.ID, s.InputRequests)
	work.MustHaveInput(s.ID, s.InputAccounts)
	work.MustHaveOutput[*transfer.BankBatch](s.ID, s.OutputBankBatchesToConsolidate)
	work.MustHaveOutput[*transfer.Account](s.ID, s.OutputAccountsToConsolidate)

	steps := pipelineSteps{}

	fullAccounts := work.NewChannel[*transfer.Account](s.ID+".FullAccounts", 0)
	steps.add(work.PipelineStep{
		ID:      s.ID + ".FilterLowAccounts",
		Outputs: work.StepOutputs(fullAccounts, s.OutputAccountsToConsolidate),
		Func: func(ctx context.Context) error {
			for {
				// Low accounts really shouldn't arrive here, but filter them out just in case.
				acc, err := work.ReceiveInput(ctx, s.InputAccounts)
				if err != nil {
					return work.DropErrInputClosed(err)
				}

				out := fullAccounts
				if acc.Balance() < s.PrefetchAmount.AmountOrZero() {
					// log a warning if this happens.
					slog.Warn(
						"PrefetchWithdrawSteps received low balance account",
						"balance", acc.Balance(),
						"prefetch_amount", s.PrefetchAmount.AmountOrZero(),
					)
					out = s.OutputAccountsToConsolidate
				}
				err = out.Send(ctx, acc)
				if err != nil {
					return fmt.Errorf("failed to send to output: %w", err)
				}
			}
		},
	})

	// split each account into a bank batch.
	bankBatches := work.NewChannel[*transfer.BankBatch](s.ID+".BankBatches", 0)
	steps.add(NewCombinedTransferSteps(&CombinedTransferSteps[*transfer.Account, *transfer.BankBatch]{
		WorkPool:           s.WorkPool,
		ID:                 s.ID + ".SplitAccountTransfer",
		InputWithdrawables: fullAccounts.ReceiveCh,
		Logger:             &transfer.NoopLogger[*transfer.Account, *transfer.BankBatch]{},
		StatsFunc: func(tsfr *transfer.Transfer[*transfer.Account, *transfer.BankBatch]) {
			s.Stats.SplitAccounts.Count(tsfr.RoundingGain(), tsfr.Amounts()...)
		},
		NewIntent: func(ctx context.Context, from *transfer.Account, _ *transfer.BankBatch) (*transfer.Intent[*transfer.Account, *transfer.BankBatch], error) {
			batch, err := s.BankBatchFunc(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get bank batch: %w", err)
			}
			return &transfer.Intent[*transfer.Account, *transfer.BankBatch]{
				Withdrawal: transfer.Withdrawal{
					Credits: int(from.Balance() / s.PrefetchAmount.AmountOrZero()),
					Amount:  s.PrefetchAmount,
				},
				From: from,
				To:   batch,
			}, nil
		},
		MaxParallel: s.MaxParallelBankBatches,
		MapOutputFunc: func(t *transfer.Transfer[*transfer.Account, *transfer.BankBatch]) (bool, bool) {
			// only output accounts with remaining balance and always keep the bank batch.
			return t.From().Balance() > 0, true
		},
		OutputWithdrawables: s.OutputAccountsToConsolidate,
		OutputDepositables:  bankBatches,
		DrainWithdrawables:  s.OutputAccountsToConsolidate,
	})...)

	// create an intent for each credit in a bank batch. These intents will be part of a group
	// per bank batch and will be collected
	// create an intent for each credit in the bank batch by repeating the same bank batch for each credit.
	intents := work.NewChannel[*transfer.Intent[transfer.RepWithdrawable[*transfer.BankBatch], *transfer.PaymentRequest]](s.ID+".Intents", 0)
	remainingBatchReps := work.NewChannel[transfer.RepWithdrawable[*transfer.BankBatch]](s.ID+".RemainingBatchReps", 0)
	steps.add(work.PipelineStep{
		ID:      s.ID + ".CreateIntents",
		Outputs: work.StepOutputs(intents, remainingBatchReps),
		Func: func(ctx context.Context) error {
			// TODO: If the lock on the batches becomes problematic,
			// pull up to MaxParallelBankBatches batches into this step and cycle through them.
			inReqs := s.InputRequests
			inBatches := bankBatches.ReceiveCh
			for inReqs != nil && inBatches != nil {
				batch, err := work.ReceiveInput(ctx, bankBatches.ReceiveCh)
				if err != nil {
					if errors.Is(err, work.ErrInputClosed) {
						inBatches = nil
						break
					}
					return err
				}

				origNumCredits := batch.NumCredits()
				rep := transfer.RepWithdrawable[*transfer.BankBatch]{
					W:     batch,
					Index: 0,
					Last:  false,
				}

				// bank batches can expiry while they are in memory. Send them to consolidate before this
				// happens. Assumes that bank batches are roughly received in time order, which should be
				// the case.
				expiresIn := batch.ExpiresIn() - s.MaxExpiryDuration
				expirationTimer := time.NewTimer(expiresIn)

				// send an intent for each received payment request until payment requests is closed,
				// or the bank batche expires.
				for rep.Index = range origNumCredits {
					var (
						req *transfer.PaymentRequest
						ok  bool
					)
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-expirationTimer.C:
					case req, ok = <-inReqs:
						if !ok {
							inReqs = nil
						}
					}

					if req == nil {
						// batch expired or inReqs was closed.
						break
					}

					rep.Last = rep.Index == origNumCredits-1
					err := intents.Send(ctx, &transfer.Intent[transfer.RepWithdrawable[*transfer.BankBatch], *transfer.PaymentRequest]{
						Withdrawal: transfer.Withdrawal{
							Credits: 1,
							Amount:  req.DesiredAmount(),
						},
						From: rep,
						To:   req,
					})
					if err != nil {
						return fmt.Errorf("failed to send output: %w", err)
					}
				}

				// it could be that we broke from the loop early. Check if we need to output a last rep.
				if !rep.Last {
					rep.Last = true
					err := remainingBatchReps.Send(ctx, rep)
					if err != nil {
						return fmt.Errorf("failed to send output: %w", err)
					}
				}
			}

			// send any remaning batches as single-element repetitions.
			if inBatches != nil {
				for {
					var (
						batch *transfer.BankBatch
						ok    bool
					)
					select {
					case batch, ok = <-inBatches:
					case <-ctx.Done():
						return fmt.Errorf("failed to receive bank batch: %w", ctx.Err())
					}
					if !ok {
						break
					}

					rep := transfer.RepWithdrawable[*transfer.BankBatch]{
						W:     batch,
						Index: 0,
						Last:  true,
					}
					err := remainingBatchReps.Send(ctx, rep)
					if err != nil {
						return fmt.Errorf("failed to send output: %w", err)
					}
				}
			}

			// fail any remaining requests. Shouldn't happen as long as the wallet shuts down properly.
			if inReqs != nil {
				for {
					var (
						req *transfer.PaymentRequest
						ok  bool
					)
					select {
					case req, ok = <-inReqs:
					case <-ctx.Done():
						return fmt.Errorf("failed to receive payment request: %w", ctx.Err())
					}
					if !ok {
						break
					}

					req.Fail(errors.New("no credits available, wallet is shutting down"))
				}
			}

			return nil
		},
	})

	transfers := work.NewChannel[*transfer.Transfer[transfer.RepWithdrawable[*transfer.BankBatch], *transfer.PaymentRequest]](s.ID+".Transfers", 0)
	steps.add(NewTransferSteps(&TransferSteps[transfer.RepWithdrawable[*transfer.BankBatch], *transfer.PaymentRequest]{
		ID:          s.ID + ".PaymentRequestTransfer",
		WorkPool:    s.WorkPool,
		MaxParallel: s.MaxParallelBankBatches,
		Logger:      &transfer.NoopLogger[transfer.RepWithdrawable[*transfer.BankBatch], *transfer.PaymentRequest]{},
		StatsFunc: func(tsfr *transfer.Transfer[transfer.RepWithdrawable[*transfer.BankBatch], *transfer.PaymentRequest]) {
			s.Stats.PaymentRequests.Count(tsfr.RoundingGain(), tsfr.Amounts()...)
		},
		Input:  intents.ReceiveCh,
		Output: transfers,
	})...)

	steps.add(work.PipelineStep{
		ID:      s.ID + ".DedupeBatches",
		Outputs: work.StepOutputs(s.OutputBankBatchesToConsolidate),
		Func: func(ctx context.Context) error {
			resultsByBatch := map[*transfer.BankBatch]*transfer.RepResults{}
			inRemaining := remainingBatchReps.ReceiveCh
			inTransfers := transfers.ReceiveCh
			for {
				var (
					rep  transfer.RepWithdrawable[*transfer.BankBatch]
					tsfr *transfer.Transfer[transfer.RepWithdrawable[*transfer.BankBatch], *transfer.PaymentRequest]
					ok   bool
				)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case rep, ok = <-inRemaining:
					if !ok {
						inRemaining = nil
					}
				case tsfr, ok = <-inTransfers:
					if !ok {
						inTransfers = nil
					} else {
						rep = tsfr.From()
					}
				}

				if inRemaining == nil && inTransfers == nil {
					break
				}

				if !ok {
					continue
				}

				results, ok := resultsByBatch[rep.W]
				if !ok {
					results = &transfer.RepResults{}
					resultsByBatch[rep.W] = results
				}
				results.Add(rep)
				if !results.Complete() {
					continue
				}

				// results are complete. Delete them and send batch to output if there are credits
				// remaining.
				delete(resultsByBatch, rep.W)
				if rep.W.NumCredits() > 0 {
					err := s.OutputBankBatchesToConsolidate.Send(ctx, rep.W)
					if err != nil {
						return fmt.Errorf("failed to send output: %w", err)
					}
				}
			}
			if len(resultsByBatch) > 0 {
				for to, results := range resultsByBatch {
					if !results.Complete() {
						// the other steps should always output a last bank batch, so these
						// results should always be complete.
						slog.Error("cleaning up incomplete bank batch")
					}
					if to.NumCredits() > 0 {
						err := s.OutputBankBatchesToConsolidate.Send(ctx, to)
						if err != nil {
							return fmt.Errorf("failed to send output: %w", err)
						}
					}
				}
			}
			return nil
		},
	})

	return steps
}
