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

import "context"

// SingleFuncApp is an app that runs a single function that shuts down when
// its context is cancelled.
type SingleFuncApp struct {
	cancel  context.CancelFunc
	runFunc func(ctx context.Context) error
}

func NewSingleFuncApp(runFunc func(ctx context.Context) error) *SingleFuncApp {
	return &SingleFuncApp{
		runFunc: runFunc,
	}
}

func (a *SingleFuncApp) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel

	return a.runFunc(ctx)
}

func (a *SingleFuncApp) Shutdown(context.Context) error {
	if a.cancel != nil {
		a.cancel()
	}
	return nil
}
