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
	"slices"
	"testing"
	"time"

	"github.com/openpcc/openpcc/anonpay/currency"
	wtest "github.com/openpcc/openpcc/anonpay/wallet/internal/test"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/transfer"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/work"
	"github.com/stretchr/testify/require"
)

func runWorkPoolWhile(t *testing.T) *work.Pool {
	wp := work.NewPool(0, 1)
	t.Cleanup(func() {
		wp.Close()
	})
	return wp
}

func produce[T any](vals ...T) <-chan T {
	ch := make(chan T)
	go func() {
		for _, val := range vals {
			ch <- val
		}
		close(ch)
	}()
	return ch
}

func paymentRequests(_ *testing.T, amounts ...int64) []*transfer.PaymentRequest {
	out := make([]*transfer.PaymentRequest, 0, len(amounts))
	for _, amount := range amounts {
		out = append(out, transfer.NewPaymentRequest(test.Must(currency.Exact(amount))))
	}
	return out
}

func paymentResults(t *testing.T, bb *transfer.BlindBank, amounts ...int64) []*transfer.PaymentResult {
	out := make([]*transfer.PaymentResult, 0, len(amounts))
	for _, amount := range amounts {
		credit := anonpaytest.MustBlindCredit(t.Context(), test.Must(currency.Exact(amount)))
		result, err := transfer.NewPaymentResult(bb, credit, 0)
		require.NoError(t, err)
		out = append(out, result)
	}
	return out
}

func bankBatches(t *testing.T, bb *transfer.BlindBank, batches ...batch) []*transfer.BankBatch {
	out := make([]*transfer.BankBatch, 0, len(batches))
	for _, b := range batches {
		isValidTestBatch(t, b)

		accounts := wtest.SeedAccounts(t, bb, 0, sum(b...))

		result, err := transfer.Process(t.Context(), &transfer.Intent[*transfer.Account, *transfer.BankBatch]{
			Withdrawal: transfer.Withdrawal{
				Credits: len(b),
				Amount:  test.Must(currency.Exact(b[0])),
			},
			From: accounts[0],
			To:   transfer.EmptyBankBatch(),
		}, &transfer.NoopLogger[*transfer.Account, *transfer.BankBatch]{})
		require.NoError(t, err)

		out = append(out, result.To())
	}

	return out
}

func runSteps(t *testing.T, workers ...work.PipelineStep) {
	p, err := work.RunPipeline(t.Context(), workers...)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancelFunc := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancelFunc()
		require.NoError(t, p.Close(ctx))
	})
}

func receiveFull[T any](ch <-chan T) <-chan []T {
	out := make(chan []T)
	go func() {
		var got []T
		for val := range ch {
			got = append(got, val)
		}
		out <- got
		close(out)
	}()
	return out
}

func drain[T any](ch <-chan T) []T {
	return <-receiveFull(ch)
}

func drain2[T1, T2 any](ch1 <-chan T1, ch2 <-chan T2) ([]T1, []T2) {
	ch1Done := receiveFull(ch1)
	ch2Done := receiveFull(ch2)
	return <-ch1Done, <-ch2Done
}

func sum(vals ...int64) int64 {
	sum := int64(0)
	for _, val := range vals {
		sum += val
	}
	return sum
}

func requireAccountBalances(t *testing.T, bb *transfer.BlindBank, wantBalances []int64, accounts ...*transfer.Account) {
	t.Helper()

	// verify balance matches expectations on the output accounts.
	seen := map[string]struct{}{}
	balances := []int64{}
	for _, acc := range accounts {
		seen[string(acc.Token().SecretBytes())] = struct{}{}
		balances = append(balances, acc.Balance())
		balance, _ := bb.Balance(t.Context(), acc.Token())
		require.Equal(t, balance, acc.Balance())
	}
	require.ElementsMatch(t, wantBalances, balances)
}

// batch is the test representation of a batch of bank credits. all values must be the same.
type batch []int64

func isValidTestBatch(t *testing.T, b batch) {
	t.Helper()

	require.GreaterOrEqual(t, len(b), 1)
	require.Equal(t, batch(slices.Repeat([]int64{b[0]}, len(b))), b)
}

func requireBankBatches(t *testing.T, wantBatches []batch, batches ...*transfer.BankBatch) {
	// ensure the batches consist of the expected credits, ignoring order.
	t.Helper()

	// sanity check the wanted batches
	for _, wantBatch := range wantBatches {
		isValidTestBatch(t, wantBatch)
	}

	gotBatches := []batch{}
	for _, batch := range batches {
		asIntSlice := slices.Repeat([]int64{batch.CreditAmount().AmountOrZero()}, batch.NumCredits())
		gotBatches = append(gotBatches, asIntSlice)
	}
	require.ElementsMatch(t, wantBatches, gotBatches)
}

func receivePaymentResponses(reqs ...*transfer.PaymentRequest) <-chan []int64 {
	responses := make(chan int64)
	for _, req := range reqs {
		go func() {
			resp := <-req.Response()
			responses <- resp.Credit.Value().AmountOrZero()
		}()
	}

	out := make(chan []int64)
	go func() {
		gotAmounts := []int64{}
		for range len(reqs) {
			gotAmounts = append(gotAmounts, <-responses)
		}
		out <- gotAmounts
	}()
	return out
}
