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

package pipeline_test

import (
	"context"
	"testing"

	"github.com/openpcc/openpcc/anonpay/wallet/internal/pipeline"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/stats"
	wtest "github.com/openpcc/openpcc/anonpay/wallet/internal/test"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/transfer"
	"github.com/openpcc/openpcc/work"
	"github.com/stretchr/testify/require"
)

func TestConsolidateSteps(t *testing.T) {
	tests := map[string]struct {
		targetBalance              int64
		bankBatches                []batch
		paymentResults             []int64
		accounts                   []int64
		wantAccounts               []int64
		wantFromBatchStats         stats.TransferCount
		wantFrompaymentResultStats stats.TransferCount
		wantFromAccountStats       stats.TransferCount
	}{
		"ok, no input": {
			targetBalance:              100,
			bankBatches:                []batch{},
			paymentResults:             []int64{},
			accounts:                   []int64{},
			wantAccounts:               []int64{},
			wantFromBatchStats:         stats.TransferCount{},
			wantFrompaymentResultStats: stats.TransferCount{},
			wantFromAccountStats:       stats.TransferCount{},
		},
		"ok, single bank batch": {
			targetBalance:              100,
			bankBatches:                []batch{{50}},
			paymentResults:             []int64{},
			accounts:                   []int64{},
			wantAccounts:               []int64{50},
			wantFromBatchStats:         stats.TransferCount{Count: 1, Amount: 50, Credits: 1},
			wantFrompaymentResultStats: stats.TransferCount{},
			wantFromAccountStats:       stats.TransferCount{},
		},
		"ok, single result": {
			targetBalance:              100,
			bankBatches:                []batch{},
			paymentResults:             []int64{50},
			accounts:                   []int64{},
			wantAccounts:               []int64{50},
			wantFromBatchStats:         stats.TransferCount{},
			wantFrompaymentResultStats: stats.TransferCount{Count: 1, Amount: 50, Credits: 1},
			wantFromAccountStats:       stats.TransferCount{},
		},
		"ok, single low account": {
			targetBalance:              100,
			bankBatches:                []batch{},
			paymentResults:             []int64{},
			accounts:                   []int64{50},
			wantAccounts:               []int64{50},
			wantFromBatchStats:         stats.TransferCount{},
			wantFrompaymentResultStats: stats.TransferCount{},
			wantFromAccountStats:       stats.TransferCount{Count: 1, Amount: 50, Credits: 1},
		},
		"ok, single low account that can't have balance exactly represented": {
			targetBalance:              100,
			bankBatches:                []batch{},
			paymentResults:             []int64{},
			accounts:                   []int64{49},
			wantAccounts:               []int64{48}, // we always round down in these test cases.
			wantFromBatchStats:         stats.TransferCount{},
			wantFrompaymentResultStats: stats.TransferCount{},
			wantFromAccountStats:       stats.TransferCount{Count: 1, Amount: 48, Credits: 1, RoundingGain: -1},
		},
		"ok, single matching account": {
			targetBalance:  100,
			bankBatches:    []batch{},
			paymentResults: []int64{},
			accounts:       []int64{100},
			wantAccounts:   []int64{100},
			// no stats as this account doesn't result in a transfer.
			wantFromBatchStats:         stats.TransferCount{},
			wantFrompaymentResultStats: stats.TransferCount{},
			wantFromAccountStats:       stats.TransferCount{},
		},
		"ok, single high account": {
			targetBalance:  100,
			bankBatches:    []batch{},
			paymentResults: []int64{},
			accounts:       []int64{101},
			wantAccounts:   []int64{101},
			// no stats as this account doesn't result in a transfer.
			wantFromBatchStats:         stats.TransferCount{},
			wantFrompaymentResultStats: stats.TransferCount{},
			wantFromAccountStats:       stats.TransferCount{},
		},
		"ok, mix of inputs combined, under target balance": {
			targetBalance:              100,
			bankBatches:                []batch{{10}},
			paymentResults:             []int64{30, 5},
			accounts:                   []int64{11},
			wantAccounts:               []int64{15 + 30 + 11},
			wantFromBatchStats:         stats.TransferCount{Count: 1, Amount: 10, Credits: 1},
			wantFrompaymentResultStats: stats.TransferCount{Count: 2, Amount: 30 + 5, Credits: 2},
			wantFromAccountStats:       stats.TransferCount{Count: 1, Amount: 11, Credits: 1},
		},
		"ok, mix of inputs combined, at target balance": {
			targetBalance:              100,
			bankBatches:                []batch{{32}},
			paymentResults:             []int64{32, 4},
			accounts:                   []int64{32},
			wantAccounts:               []int64{100},
			wantFromBatchStats:         stats.TransferCount{Count: 1, Amount: 32, Credits: 1},
			wantFrompaymentResultStats: stats.TransferCount{Count: 2, Amount: 32 + 4, Credits: 2},
			wantFromAccountStats:       stats.TransferCount{Count: 1, Amount: 32, Credits: 1},
		},
		"ok, mix of inputs combined, over target balance": {
			targetBalance:              100,
			bankBatches:                []batch{{32}},
			paymentResults:             []int64{32, 5},
			accounts:                   []int64{32},
			wantAccounts:               []int64{101},
			wantFromBatchStats:         stats.TransferCount{Count: 1, Amount: 32, Credits: 1},
			wantFrompaymentResultStats: stats.TransferCount{Count: 2, Amount: 32 + 5, Credits: 2},
			wantFromAccountStats:       stats.TransferCount{Count: 1, Amount: 32, Credits: 1},
		},
		"ok, mix of inputs combined, several accounts": {
			targetBalance:              100,
			bankBatches:                []batch{{50}, {50}},
			paymentResults:             []int64{50, 50},
			accounts:                   []int64{50, 50},
			wantAccounts:               []int64{100, 100, 100},
			wantFromBatchStats:         stats.TransferCount{Count: 2, Amount: 50 + 50, Credits: 2},
			wantFrompaymentResultStats: stats.TransferCount{Count: 2, Amount: 50 + 50, Credits: 2},
			wantFromAccountStats:       stats.TransferCount{Count: 2, Amount: 50 + 50, Credits: 2},
		},
		"ok, mix of inputs combined, several accounts, with remaining account under target balance": {
			targetBalance:              100,
			bankBatches:                []batch{{50}, {50}},
			paymentResults:             []int64{50, 50, 50},
			accounts:                   []int64{50, 50},
			wantAccounts:               []int64{100, 100, 100, 50},
			wantFromBatchStats:         stats.TransferCount{Count: 2, Amount: 50 + 50, Credits: 2},
			wantFrompaymentResultStats: stats.TransferCount{Count: 3, Amount: 50 + 50 + 50, Credits: 3},
			wantFromAccountStats:       stats.TransferCount{Count: 2, Amount: 50 + 50, Credits: 2},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			wp := runWorkPoolWhile(t)

			_, bb := wtest.NewBlindBank(t)

			batches := bankBatches(t, bb, tc.bankBatches...)
			payResults := paymentResults(t, bb, tc.paymentResults...)
			accounts := wtest.SeedAccounts(t, bb, 0, tc.accounts...)

			stats := pipeline.NewConsolidateStats()
			outAccounts := work.NewChannel[*transfer.Account]("outputAccounts", 0)
			steps := pipeline.NewConsolidateSteps(&pipeline.ConsolidateSteps{
				ID:                              "test",
				Stats:                           stats,
				WorkPool:                        wp,
				MaxParallelConsolidatedAccounts: 1,
				TargetBalance:                   tc.targetBalance,
				AccountFunc: func(ctx context.Context) (*transfer.Account, error) {
					return transfer.EmptyBankAccount(ctx, bb, 0)
				},
				InputBankBatches:    produce(batches...),
				InputPaymentResults: produce(payResults...),
				InputAccounts:       produce(accounts...),
				Output:              outAccounts,
			})

			runSteps(t, steps...)

			gotAccounts := drain(outAccounts.ReceiveCh)
			requireAccountBalances(t, bb, tc.wantAccounts, gotAccounts...)

			require.Equal(t, tc.wantFromAccountStats, stats.FromAccounts.Read())
			require.Equal(t, tc.wantFromBatchStats, stats.FromBankBatches.Read())
			require.Equal(t, tc.wantFrompaymentResultStats, stats.FromPaymentResults.Read())
		})
	}
}
