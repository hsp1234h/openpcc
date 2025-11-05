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

	"github.com/openpcc/openpcc/anonpay"
)

// IntentLogger logs the intent to process a Transfer and returns a ProgressLogger for that specific transfer.
//
// Useful for tracking statistics and crash recovery.
type IntentLogger[W Withdrawable, D Depositable] interface {
	LogIntent(ctx context.Context, transferID []byte, intent *Intent[W, D]) (ProgressLogger, error)
}

type ProgressLogger interface {
	LogWithdrawOK(roundingGain int64, credits []*anonpay.BlindedCredit) error
	LogFinishErrorOK(err error) error
	LogFinishDepositOK() error
	LogFinishUnexpectedError(err error) error
}

// NoopLogger is an IntentLogger that doesn't do anything and will never return an error. Useful for testing
// and as a placeholder while we implement crash recovery.
type NoopLogger[W Withdrawable, D Depositable] struct{}

func (*NoopLogger[W, D]) LogIntent(_ context.Context, _ []byte, _ *Intent[W, D]) (ProgressLogger, error) {
	return noopLoggerProgress{}, nil
}

type noopLoggerProgress struct{}

func (noopLoggerProgress) LogWithdrawOK(_ int64, _ []*anonpay.BlindedCredit) error {
	return nil
}

func (noopLoggerProgress) LogFinishErrorOK(_ error) error {
	return nil
}

func (noopLoggerProgress) LogFinishDepositOK() error {
	return nil
}

func (noopLoggerProgress) LogFinishUnexpectedError(_ error) error {
	return nil
}
