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

package delay

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

// Delayed wraps a value to indicate it has been delayed by a specific amount of time.
type Delayed[T any] struct {
	// Delay indicates the amount of time the delay package
	// has delayed this subject.
	//
	// It doesn't account for waiting time in channels and/or goroutines, only
	// the explicit delay applied to this value.
	Delay time.Duration
	V     T
}

func ValueFor[T any](ctx context.Context, s T, delay time.Duration) (Delayed[T], error) {
	err := For(ctx, delay)
	return Delayed[T]{
		Delay: delay,
		V:     s,
	}, err
}

func ValueUpTo[T any](ctx context.Context, s T, maxDelay time.Duration) (Delayed[T], error) {
	delay, err := UpTo(ctx, maxDelay)
	if err != nil {
		return Delayed[T]{}, err
	}

	return Delayed[T]{
		Delay: delay,
		V:     s,
	}, nil
}

func For(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func UpTo(ctx context.Context, maxDelay time.Duration) (time.Duration, error) {
	if maxDelay == 0 {
		return time.Duration(0), nil
	}

	delay, err := randDuration(maxDelay)
	if err != nil {
		return 0, err
	}

	timer := time.NewTimer(delay)
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-timer.C:
		return delay, nil
	}
}

func randDuration(maxDuration time.Duration) (time.Duration, error) {
	d, err := rand.Int(rand.Reader, big.NewInt(int64(maxDuration)))
	if err != nil {
		return 0, fmt.Errorf("failed to read random duration: %w", err)
	}
	return time.Duration(d.Int64()), nil
}
