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
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/banking"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/pipeline"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/transfer"
	"github.com/openpcc/openpcc/work"
)

type Config struct {
	// SourceAmount is the size of the credits that will get withdrawn from
	// the source. These credits will get stored in fresh blind bank accounts,
	// after which they will be used to pay for requests.
	SourceAmount int64 `yaml:"source_amount"`
	// PrefetchAmount determines the size of locally stored credits that are ready
	// for immediate withdrawal. Due to the anonymization process it takes a while before
	// a credit can be withdrawn, to maintain target parallelism the wallet will keep a
	// store a number of credits locally.
	PrefetchAmount int64 `yaml:"prefetch_amount"`
	// MaxParallel is the maximum number of parallel requests the wallet can make. This
	// settings determines the number of workers that will be spun up and the number of
	// credits that will be stored locally. Defaults to 4.
	MaxParallel int `yaml:"max_parallel"`
	// MaxDelay is the maximum delay that will be applied between withdraw/deposit operations
	// that should not be linked together. Defaults to 5s.
	MaxDelay time.Duration `yaml:"max_delay"`
	// AvgPaymentDuration is the average amount of time it takes before a payment is completed.
	// Used to compute the number of workers required to sustain MaxParallel. Defaults to 150ms.
	AvgPaymentDuration time.Duration `yaml:"avg_payment_duration"`

	// Option to override configuration while tweak performance.
	DebugConfig *DebugConfig
}

type DebugConfig struct {
	TotalWorkers                      int
	MaxParallelSourceAccountTransfers int
	MaxParallelBankBatchTransfers     int
	MaxParallelDepositTransfers       int
	LogWorkPoolStats                  bool
}

type Wallet struct {
	closeMu    *sync.RWMutex
	closed     bool
	paymentsWG *sync.WaitGroup

	debugCfg *DebugConfig

	sourceAmount   int64
	prefetchAmount int64
	workPool       *work.Pool
	pipeline       *work.Pipeline
	blindbank      *transfer.BlindBank
	maxDelay       time.Duration

	stats *pipeline.WalletStats

	requests chan<- *transfer.PaymentRequest
	results  chan<- *transfer.PaymentResult
}

func New(cfg Config, payee *anonpay.Payee, bank banking.BlindBankContract, srcSvc transfer.SourceService) (*Wallet, error) {
	if cfg.SourceAmount <= 0 || cfg.PrefetchAmount <= 0 {
		return nil, fmt.Errorf("invalid amounts: %d %d", cfg.SourceAmount, cfg.PrefetchAmount)
	}
	if cfg.SourceAmount < cfg.PrefetchAmount {
		return nil, fmt.Errorf("prefetch amount %d must be equal to or greater than source amount %d", cfg.PrefetchAmount, cfg.SourceAmount)
	}

	sourceVal, err := currency.Exact(cfg.SourceAmount)
	if err != nil {
		return nil, fmt.Errorf("source amount %d currency error: %w", cfg.SourceAmount, err)
	}

	prefetchVal, err := currency.Exact(cfg.PrefetchAmount)
	if err != nil {
		return nil, fmt.Errorf("prefetch amount %d currency error: %w", cfg.SourceAmount, err)
	}

	if cfg.MaxParallel <= 0 {
		cfg.MaxParallel = 4
	}
	if cfg.AvgPaymentDuration <= 0 {
		cfg.AvgPaymentDuration = 150 * time.Millisecond
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 5 * time.Second
	}

	avgOperationDuration := 1 * time.Second

	bb := transfer.NewBlindBank(payee, bank)

	// estimate how many batches we should have available to sustain the maximum parallelism.
	creditsPerBatch := int(cfg.SourceAmount / cfg.PrefetchAmount)
	consumedCreditsPerSecond := (1.0 / cfg.AvgPaymentDuration.Seconds()) * float64(cfg.MaxParallel)
	consumedBatchesPerSecond := consumedCreditsPerSecond / float64(creditsPerBatch)

	// last deposit takes 0 due to being in memory.
	// batches are the result of a "split transfer", where a source account is split into a bank batch.
	avgSplitTransfer := transfer.EstimateAvgDuration(cfg.MaxDelay, time.Second, 0)
	maxBankBatches := parellismToSustainConsumption(consumedBatchesPerSecond, avgSplitTransfer)

	// withdraw and deposit are both a single remote operation when transferring from source to a new bank account.
	avgSrcTransfer := transfer.EstimateAvgDuration(cfg.MaxDelay, avgOperationDuration, avgOperationDuration)
	maxSrcAccounts := parellismToSustainConsumption(consumedBatchesPerSecond, avgSrcTransfer)

	// worst case each consumed credit will result in a deposit.
	avgConsolidationTransfer := transfer.EstimateAvgDuration(cfg.MaxDelay, 0, avgOperationDuration)
	maxDeposits := parellismToSustainConsumption(consumedCreditsPerSecond, avgConsolidationTransfer)

	if cfg.DebugConfig != nil {
		if cfg.DebugConfig.MaxParallelSourceAccountTransfers != 0 {
			maxSrcAccounts = cfg.DebugConfig.MaxParallelSourceAccountTransfers
		}
		if cfg.DebugConfig.MaxParallelBankBatchTransfers != 0 {
			maxBankBatches = cfg.DebugConfig.MaxParallelBankBatchTransfers
		}
		if cfg.DebugConfig.MaxParallelDepositTransfers != 0 {
			maxDeposits = cfg.DebugConfig.MaxParallelDepositTransfers
		}
	}

	workers := maxBankBatches + maxSrcAccounts + maxDeposits
	if cfg.DebugConfig != nil && cfg.DebugConfig.TotalWorkers != 0 {
		workers = cfg.DebugConfig.TotalWorkers
	}

	// work queue length of 0, as we don't need buffering of jobs.
	wp := work.NewPool(0, workers)

	// create wallet pipeline.
	signal := work.NewChannel[struct{}]("wallet.Signal", 0)
	withdrawals := work.NewChannel[*transfer.PaymentRequest]("wallet.Withdrawals", 0)
	deposits := work.NewChannel[*transfer.PaymentResult]("wallet.Deposits", 0)

	steps := []work.PipelineStep{}
	steps = append(steps, pipeline.NewRootStep(&pipeline.RootStep{
		ID:     "root",
		Output: signal,
	}))
	src := transfer.NewSource(srcSvc, cfg.MaxDelay)

	stats := pipeline.NewWalletStats()
	steps = append(steps, pipeline.NewWalletSteps(&pipeline.WalletSteps{
		ID:                        "wallet",
		Stats:                     stats,
		WorkPool:                  wp,
		SourceAmount:              sourceVal,
		PrefetchAmount:            prefetchVal,
		MaxParallelSourceAccounts: maxSrcAccounts,
		MaxParallelBankBatches:    maxBankBatches,
		MaxParallelPaymentResults: maxDeposits,
		AccountFunc: func(ctx context.Context) (*transfer.Account, error) {
			return transfer.EmptyBankAccount(ctx, bb, cfg.MaxDelay)
		},
		SourceFunc: func(_ context.Context) (*transfer.Source, error) {
			return src, nil
		},
		BankBatchFunc: func(_ context.Context) (*transfer.BankBatch, error) {
			return transfer.EmptyBankBatch(), nil
		},
		InputSignal:                  signal.ReceiveCh,
		InputPrefetchPaymentRequests: withdrawals.ReceiveCh,
		InputPaymentResults:          deposits.ReceiveCh,
	})...)

	p, err := work.RunPipeline(context.Background(), steps...)
	if err != nil {
		wp.Close()
		return nil, fmt.Errorf("failed to run pipeline: %w", err)
	}

	return &Wallet{
		closeMu:    &sync.RWMutex{},
		closed:     false,
		paymentsWG: &sync.WaitGroup{},

		workPool:       wp,
		prefetchAmount: cfg.PrefetchAmount,
		sourceAmount:   cfg.SourceAmount,
		pipeline:       p,
		blindbank:      bb,
		maxDelay:       cfg.MaxDelay,
		stats:          stats,
		requests:       withdrawals.SendCh,
		results:        deposits.SendCh,
	}, nil
}

// BeginPayment begins a payment or returns an error. It is up to the caller to complete the returned
// payment. All returned payments must be completed by calling Success or Cancel on the payment.
func (w *Wallet) BeginPayment(ctx context.Context, amount int64) (Payment, error) {
	if w.debugCfg != nil && w.debugCfg.LogWorkPoolStats {
		slog.Debug("workpool stats", "total_workers", w.workPool.Workers(), "idle_workers", w.workPool.IdleWorkers())
	}

	// round amount up.
	// TODO: The bank client also does its own rounding, we should probably drop that once we switch
	// to wallet as it should be responsibility of the caller to decide whether to round or not.
	val, err := currency.Rounded(float64(amount), 1.0)
	if err != nil {
		return nil, fmt.Errorf("failed to round amount: %w", err)
	}

	if val.AmountOrZero() > w.prefetchAmount {
		// TODO: temporary error while wallet doesn't support ad-hoc withdrawals yet.
		return nil, fmt.Errorf("wallet does not support ad-hoc withdrawals yet. please withdraw %d or less, got %d", w.prefetchAmount, val.AmountOrZero())
	}

	// check if the wallet is closed.
	w.closeMu.RLock()
	if w.closed {
		w.closeMu.RUnlock()
		return nil, errors.New("wallet is closed")
	}
	w.paymentsWG.Add(1)
	w.closeMu.RUnlock()

	// enqueue the request so that the pipeline can make deposit into it.
	req := transfer.NewPaymentRequest(val)
	timer := time.NewTimer(time.Millisecond)
	select {
	case w.requests <- req:
	case <-ctx.Done():
		w.paymentsWG.Done()
		return nil, ctx.Err()
	case <-timer.C:
		slog.Warn("Could not immediately schedule payment. Consider increasing concurrent_requests_target")
		select {
		case w.requests <- req:
		case <-ctx.Done():
			w.paymentsWG.Done()
			return nil, ctx.Err()
		}
	}

	// begin a payment for the request. Waits for the request to resolve
	// or for the context to be cancelled.
	return w.beginPaymentForRequest(ctx, req)
}

func (w *Wallet) Close(ctx context.Context) error {
	w.closeMu.Lock()
	if w.closed {
		w.closeMu.Unlock()
		return nil
	}
	w.closed = true
	defer w.closeMu.Unlock()
	defer func() {
		w.workPool.Close()
	}()

	// wait for withdrawals and deposits to finish.
	w.paymentsWG.Wait()

	// close the inputs to the pipeline so it can shut down.
	close(w.requests)
	close(w.results)

	// then close the entire pipeline, hard close when the context is cancelled.
	err := w.pipeline.Close(ctx)
	if err != nil {
		return fmt.Errorf("failed to close pipeline: %w", err)
	}
	return nil
}

// Status is a snapshot of a wallet's current state in terms of credit
// availability and spend. It is the return type for the Status() method of the Wallet
// interface.
type Status struct {
	// CreditsSpent is the total amount of credit spent from the wallet over its lifetime
	CreditsSpent int64 `json:"credits_spent"`
	// CreditsHeld is the total amount of credits currently held in the wallet, including
	// credits that are available to be spent and credits that are being processed. This
	// is the amount of credits that would be lost if the client were to crash without
	// properly closing the wallet.
	CreditsHeld int64 `json:"credits_held"`
	// CreditsAvailable is the total number of credits available to be spent immediately
	CreditsAvailable int64 `json:"credits_available"`
}

// String returns a human-readable string representation of the wallet status.
func (s Status) String() string {
	const tmpl = `¤%d ready to use
¤%d being processed`
	return fmt.Sprintf(tmpl, s.CreditsAvailable, s.CreditsHeld-s.CreditsAvailable)
}

// Status will return the status of the wallet.
func (w *Wallet) Status() Status {
	s := w.stats.CalcWalletStatus()
	return Status{
		CreditsSpent:     s.SpendCreditCount.Amount,
		CreditsHeld:      s.AmountInAccounts + s.BankBatchCreditCount.Amount,
		CreditsAvailable: s.BankBatchCreditCount.Amount,
	}
}

func (*Wallet) SetDefaultCreditAmount(int64) error {
	return errors.New("not implemented yet")
}

func parellismToSustainConsumption(consumedPerSecond float64, produceDuration time.Duration) int {
	resultsPerSecondPerProduce := 1.0 / produceDuration.Seconds()
	return int(max(1, math.Ceil(consumedPerSecond/resultsPerSecondPerProduce)))
}
