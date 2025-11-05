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
	"errors"
	"sync"
	"time"
)

var errorShutdownTimeout = 30 * time.Second

type groupApp struct {
	app               App
	groupCtx          context.Context
	errorShutdownFunc func(App) error
}

func (a *groupApp) run() error {
	// run the app in a separate go routine so we can monitor shutdown signal
	errCh := make(chan error)
	go func() {
		errCh <- a.app.Run()
	}()

	// wait for the app to complete or for the group context to be done.
	select {
	case err := <-errCh:
		return err
	case <-a.groupCtx.Done():
		// shutdown the app
		err := a.errorShutdownFunc(a.app)
		// wait for separate goroutine to return and combine the results.
		return errors.Join(err, <-errCh)
	}
}

type Multi struct {
	groupCtxCancel context.CancelFunc
	apps           []groupApp
}

func NewMulti(apps ...App) *Multi {
	groupCtx, groupCtxCancel := context.WithCancel(context.Background())
	multiApps := make([]groupApp, 0, len(apps))
	for _, a := range apps {
		multiApps = append(multiApps, groupApp{
			app:      a,
			groupCtx: groupCtx,
			errorShutdownFunc: func(a App) error {
				ctx, cancel := context.WithTimeout(context.Background(), errorShutdownTimeout)
				defer cancel()
				return a.Shutdown(ctx)
			},
		})
	}

	return &Multi{
		groupCtxCancel: groupCtxCancel,
		apps:           multiApps,
	}
}

// ErrorShutdownFunc provides a way to disable the default error shutdown behaviour.
func (m *Multi) ErrorShutdownFunc(shutdownFunc func(App) error) {
	for i := range m.apps {
		m.apps[i].errorShutdownFunc = shutdownFunc
	}
}

func (m *Multi) Run() error {
	if len(m.apps) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	errs := make(chan error)

	for _, a := range m.apps {
		wg.Go(func() {
			err := a.run()
			if err != nil {
				errs <- err
				// shutdown the other apps
				m.groupCtxCancel()
			}
		})
	}

	// close errs when all goroutines are done
	go func() {
		wg.Wait()
		close(errs)
	}()

	var outErr error
	for err := range errs {
		outErr = errors.Join(outErr, err)
	}

	return outErr
}

func (m *Multi) Shutdown(ctx context.Context) error {
	if len(m.apps) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	errs := make(chan error)

	for _, a := range m.apps {
		wg.Go(func() {
			err := a.app.Shutdown(ctx)
			if err != nil {
				errs <- err
			}
		})
	}

	// close errs when all goroutines are done
	go func() {
		wg.Wait()
		close(errs)
	}()

	var outErr error
	for err := range errs {
		outErr = errors.Join(outErr, err)
	}

	return outErr
}
