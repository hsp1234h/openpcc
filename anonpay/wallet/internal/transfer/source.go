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
	"time"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
)

type SourceService interface {
	Withdraw(ctx context.Context, id []byte, amount currency.Value) (*anonpay.BlindedCredit, error)
	Deposit(ctx context.Context, id []byte, credits ...*anonpay.BlindedCredit) error
}

// Source represents the source of credits.
type Source struct {
	svc   SourceService
	delay time.Duration
}

func NewSource(svc SourceService, maxDelay time.Duration) *Source {
	return &Source{
		svc:   svc,
		delay: maxDelay,
	}
}

func (*Source) origin() creditOrigin {
	return sourceOrigin
}

func (*Source) allowedOrigins() []creditOrigin {
	// Credits from source and blindbank can be deposited in accounts in the blind bank.
	return []creditOrigin{
		sourceOrigin,
		blindbankOrigin,
	}
}

func (s *Source) maxDelay() time.Duration {
	return s.delay
}

// nolint: unparam
func (s *Source) withdraw(ctx context.Context, id []byte, w Withdrawal) ([]*anonpay.BlindedCredit, int64, error) {
	if w == FullWithdrawal {
		return nil, 0, errors.New("can't do a full withdrawal from source")
	}
	if w.Credits != 1 {
		return nil, 0, fmt.Errorf("can only withdraw a single credit from source, attempting to withdraw %d", w.Credits)
	}

	credit, err := s.svc.Withdraw(ctx, id, w.Amount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to withdraw from source service: %w", err)
	}
	return []*anonpay.BlindedCredit{credit}, 0, nil
}

func (s *Source) deposit(ctx context.Context, id []byte, credits ...*anonpay.BlindedCredit) error {
	return s.svc.Deposit(ctx, id, credits...)
}
