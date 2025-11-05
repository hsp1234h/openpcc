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
	"log/slog"
	"sync"
	"time"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/transfer"
)

type Payment interface {
	Success(unspend *anonpay.UnblindedCredit) error
	Credit() *anonpay.BlindedCredit
	Cancel() error
}

type payment struct {
	mu        *sync.Mutex
	w         *Wallet
	credit    *anonpay.BlindedCredit
	completed bool
}

func (w *Wallet) beginPaymentForRequest(ctx context.Context, req *transfer.PaymentRequest) (*payment, error) {
	p := &payment{
		mu:        &sync.Mutex{},
		w:         w,
		credit:    nil,
		completed: false,
	}

	ch := req.Response()
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		// ensure the result of this payment request gets returned to the pipeline.
		go p.waitForDanglingResponse(ch)
		return nil, ctx.Err()
	case resp := <-ch:
		if resp.Err != nil {
			return nil, resp.Err
		}
		p.credit = resp.Credit
		return p, nil
	case <-timer.C:
		slog.Warn("Could not immediately begin payment. Consider increasing concurrent_requests_target")
		select {
		case <-ctx.Done():
			// ensure the result of this payment request gets returned to the pipeline.
			go p.waitForDanglingResponse(ch)
			return nil, ctx.Err()
		case resp := <-ch:
			if resp.Err != nil {
				return nil, resp.Err
			}
			p.credit = resp.Credit
			return p, nil
		}
	}
}

func (p *payment) waitForDanglingResponse(ch <-chan transfer.PaymentResponse) {
	resp := <-ch
	if resp.Err != nil {
		return
	}
	p.credit = resp.Credit
	err := p.Cancel()
	if err != nil {
		// shouldn't really happen as it indicates that the response for a cancelled
		// payment request contained an invalid credit.
		slog.Error("failed to cancel payment for dangling payment response", "error", err)
	}
}

func (p *payment) complete(hasUnspend bool, unspend anonpay.AnyCredit) error {
	// mark the payment as done so the wallet can close.
	defer p.w.paymentsWG.Done()
	if !hasUnspend {
		return nil
	}

	result, err := transfer.NewPaymentResult(p.w.blindbank, unspend, p.w.maxDelay)
	if err != nil {
		return fmt.Errorf("failed to create deposit: %w", err)
	}
	p.w.stats.PaymentResults.Count(0, unspend.Value())

	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	select {
	case p.w.results <- result:
	case <-timer.C:
		slog.Warn("Could not immediately complete payment. Consider increasing concurrent_requests_target")
		p.w.results <- result
	}

	return nil
}

func (p *payment) Credit() *anonpay.BlindedCredit {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.credit
}

func (p *payment) Success(unspend *anonpay.UnblindedCredit) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.completed {
		return nil
	}
	p.completed = true
	return p.complete(unspend != nil, unspend)
}

func (p *payment) Cancel() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.completed {
		return nil
	}
	p.completed = true
	return p.complete(true, p.credit)
}
