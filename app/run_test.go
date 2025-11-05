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

package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/openpcc/openpcc/app"
	"github.com/stretchr/testify/require"
)

type testApp struct {
	runFunc      func() error
	shutdownFunc func(ctx context.Context) error
}

func (a *testApp) Run() error {
	if a.runFunc == nil {
		return nil
	}

	return a.runFunc()
}

func (a *testApp) Shutdown(ctx context.Context) error {
	if a.shutdownFunc == nil {
		return nil
	}

	return a.shutdownFunc(ctx)
}

func TestRun(t *testing.T) {
	t.Run("ok, context cancelled while app is running, calls shutdown", func(t *testing.T) {
		shuttingDown := make(chan struct{})
		running := make(chan struct{})
		a := &testApp{
			runFunc: func() error {
				close(running)
				<-shuttingDown
				return nil
			},
			shutdownFunc: func(_ context.Context) error {
				close(shuttingDown)
				return nil
			},
		}

		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			<-running
			cancel()
		}()

		code := app.Run(ctx, a, nil)
		require.Equal(t, 0, code)
	})

	t.Run("ok, custom context for shutdown", func(t *testing.T) {
		beginShuttingDown := make(chan struct{})
		shuttingDown := make(chan struct{})
		running := make(chan struct{})
		a := &testApp{
			runFunc: func() error {
				close(running)
				<-shuttingDown
				return nil
			},
			shutdownFunc: func(ctx context.Context) error {
				close(beginShuttingDown)
				<-ctx.Done()
				close(shuttingDown)
				return nil
			},
		}

		runCtx, runCancel := context.WithCancel(t.Context())
		go func() {
			<-running
			runCancel()
		}()

		shutdownCtx, shutdownCancel := context.WithCancel(t.Context())
		go func() {
			<-beginShuttingDown
			shutdownCancel()
		}()

		shutdownCancelCalled := false
		code := app.Run(runCtx, a, func() (context.Context, context.CancelFunc) {
			return shutdownCtx, func() {
				shutdownCancelCalled = true
			}
		})
		require.Equal(t, 0, code)
		require.True(t, shutdownCancelCalled)
	})

	t.Run("ok, context cancelled before app is running, calls shutdown", func(t *testing.T) {
		shuttingDown := make(chan struct{})
		a := &testApp{
			runFunc: func() error {
				<-shuttingDown
				return nil
			},
			shutdownFunc: func(_ context.Context) error {
				close(shuttingDown)
				return nil
			},
		}

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		code := app.Run(ctx, a, nil)
		require.Equal(t, 0, code)
	})

	t.Run("ok, context cancelled after app has ran, does not call shutdown", func(t *testing.T) {
		// this all shouldn't really happen, but test case is here to make sure nothing is broken.

		shutdownWasCalled := false
		a := &testApp{
			runFunc: func() error {
				return nil
			},
			shutdownFunc: func(_ context.Context) error {
				// might exit before
				shutdownWasCalled = true
				return nil
			},
		}

		ctx, cancel := context.WithCancel(t.Context())

		code := app.Run(ctx, a, nil)
		cancel()
		require.Equal(t, 0, code)
		require.False(t, shutdownWasCalled)
	})

	t.Run("fail, run returns error", func(t *testing.T) {
		a := &testApp{
			runFunc: func() error {
				return errors.New("run error")
			},
			shutdownFunc: func(_ context.Context) error {
				return nil
			},
		}

		code := app.Run(t.Context(), a, nil)
		require.Equal(t, 1, code)
	})

	t.Run("fail, shutdown returns error", func(t *testing.T) {
		shuttingDown := make(chan struct{})
		running := make(chan struct{})
		a := &testApp{
			runFunc: func() error {
				close(running)
				<-shuttingDown
				return nil
			},
			shutdownFunc: func(_ context.Context) error {
				close(shuttingDown)
				return errors.New("shutdown error")
			},
		}

		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			<-running
			cancel()
		}()

		code := app.Run(ctx, a, nil)
		require.Equal(t, 1, code)
	})

	t.Run("fail, run and shutdown return error", func(t *testing.T) {
		shuttingDown := make(chan struct{})
		running := make(chan struct{})
		a := &testApp{
			runFunc: func() error {
				close(running)
				<-shuttingDown
				return errors.New("run error")
			},
			shutdownFunc: func(_ context.Context) error {
				close(shuttingDown)
				return errors.New("shutdown error")
			},
		}

		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			<-running
			cancel()
		}()

		code := app.Run(ctx, a, nil)
		require.Equal(t, 1, code)
	})
}
