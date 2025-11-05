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
	"fmt"
	"sync"
	"testing"

	"github.com/openpcc/openpcc/app"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiApp(t *testing.T) {
	t.Run("ok, no apps", func(t *testing.T) {
		multi := app.NewMulti()

		err := multi.Run()
		require.NoError(t, err)
	})

	for _, nr := range []int{1, 2, 3, 10} {
		name := fmt.Sprintf("ok, run %d apps", nr)
		t.Run(name, func(t *testing.T) {
			var wg sync.WaitGroup

			apps := []app.App{}

			for range nr {
				running := make(chan struct{})
				done := make(chan struct{})
				apps = append(apps, &testApp{
					runFunc: func() error {
						close(running)
						<-done
						return nil
					},
				})

				wg.Add(1)
				go func() {
					<-running
					close(done)
					wg.Done()
				}()
			}

			multi := app.NewMulti(apps...)
			err := multi.Run()
			require.NoError(t, err)

			wg.Wait()
		})
	}

	for _, nr := range []int{1, 2, 3, 10} {
		name := fmt.Sprintf("ok, run and shutdown %d apps", nr)
		t.Run(name, func(t *testing.T) {
			var wg sync.WaitGroup
			apps := []app.App{}

			wg.Add(nr)
			for range nr {
				done := make(chan struct{})
				a := &testApp{
					runFunc: func() error {
						wg.Done()
						<-done
						return nil
					},
					shutdownFunc: func(_ context.Context) error {
						close(done)
						return nil
					},
				}
				apps = append(apps, a)
			}

			multi := app.NewMulti(apps...)

			shutdownChecked := make(chan struct{})
			go func() {
				wg.Wait()
				err := multi.Shutdown(t.Context())
				require.NoError(t, err)
				close(shutdownChecked)
			}()

			err := multi.Run()
			require.NoError(t, err)
			<-shutdownChecked
		})
	}

	t.Run("fail, run errors are propagated", func(t *testing.T) {
		err1 := errors.New("error 1")
		err2 := errors.New("error 2")

		app1 := &testApp{
			runFunc: func() error {
				return err1
			},
		}

		app2 := &testApp{
			runFunc: func() error {
				return err2
			},
		}

		multi := app.NewMulti(app1, app2)
		err := multi.Run()

		require.Error(t, err)
		require.ErrorIs(t, err, err1)
		require.ErrorIs(t, err, err2)
	})

	t.Run("fail, one app exits with error, shuts down other apps", func(t *testing.T) {
		aFail := &testApp{
			runFunc: func() error {
				return assert.AnError
			},
		}

		running := make(chan struct{})
		wasShutdown := false
		aWaitForShutdown := &testApp{
			runFunc: func() error {
				<-running
				return nil
			},
			shutdownFunc: func(ctx context.Context) error {
				close(running)
				wasShutdown = true
				return nil
			},
		}

		multi := app.NewMulti(
			aFail,
			aWaitForShutdown,
		)

		err := multi.Run()
		require.ErrorIs(t, err, assert.AnError)
		require.True(t, wasShutdown)
	})

	t.Run("fail, shutdown errors are propagated", func(t *testing.T) {
		err1 := errors.New("error 1")
		err2 := errors.New("error 2")

		app1 := &testApp{
			runFunc: func() error {
				return nil
			},
			shutdownFunc: func(ctx context.Context) error {
				return err1
			},
		}

		app2 := &testApp{
			runFunc: func() error {
				return nil
			},
			shutdownFunc: func(ctx context.Context) error {
				return err2
			},
		}

		multi := app.NewMulti(app1, app2)

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			err := multi.Run()
			require.NoError(t, err)
		}()

		err := multi.Shutdown(t.Context())
		require.Error(t, err)
		require.ErrorIs(t, err, err1)
		require.ErrorIs(t, err, err2)
	})
}
