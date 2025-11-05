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

package app

import (
	"context"
	"log/slog"
	"time"
)

var runTimeoutAfterGracefulShutdown = 30 * time.Second

// App is an application that can run and be shutdown gracefully.
//
// Calling Shutdown must cause Run to exit.
//
// If run exits before Shutdown can be called, it is assumed
// that Shutdown no longer needs to be called.
type App interface {
	Run() error
	Shutdown(ctx context.Context) error
}

type ShutdownCtxFunc func() (context.Context, context.CancelFunc)

// Run runs the given app until ctx is cancelled.
//
// shutdownCtxFunc is an optional factory function to allow the caller to provide a shutdown
// context. This context will be provided to the app when a graceful shutdown is triggered.
//
// If shutdownCtxFunc is nil, context.Background() will be used as the graceful shutdown context.
func Run(ctx context.Context, a App, shutdownCtxFunc ShutdownCtxFunc) int {
	if shutdownCtxFunc == nil {
		shutdownCtxFunc = func() (context.Context, context.CancelFunc) {
			return context.Background(), func() {}
		}
	}

	runDone := make(chan struct{}) // closed by run goroutine
	errs := make(chan error)       // closed by shutdown goroutine

	// run goroutine
	go func() {
		defer func() {
			close(runDone)
		}()

		err := a.Run()
		if err != nil {
			slog.ErrorContext(ctx, "failed to run app", "error", err)
		}
		errs <- err
	}()

	// shutdown goroutine
	go func() {
		defer func() {
			close(errs)
		}()

		// wait for the run goroutine to exit early or context to be cancelled.
		select {
		case <-runDone:
		case <-ctx.Done(): // context was cancelled, begin shutdown.
			slog.InfoContext(ctx, "Shutting down gracefully", "reason", ctx.Err())

			shutdownCtx, shutdownCancel := shutdownCtxFunc()
			defer shutdownCancel()

			err := a.Shutdown(shutdownCtx)
			if err != nil {
				slog.ErrorContext(ctx, "Failed to shutdown gracefully", "error", err)
			}

			// wait for run goroutine to finish, or timeout to pass.
			select {
			case <-runDone:
			case <-time.After(runTimeoutAfterGracefulShutdown):
			}
			errs <- err
		}
	}()

	code := 0
	for err := range errs {
		if err != nil {
			code = 1
		}
	}

	return code
}
