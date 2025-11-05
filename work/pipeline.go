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

package work

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
)

// PipelineStep is a step in a pipeline.
type PipelineStep struct {
	// ID is the identifier of the worker, should be unique per pipeline.
	ID string

	// Outputs are (shared) outputs this step writes to. The pipeline will call the appropriate
	// closer after all steps referencing that output are done. Outputs are identified by their ID, the
	// key in this map.
	//
	// [Run] will return an error if multiple steps use the same ID to reference different closers.
	//
	// Outputs should not be modified after a worker has been provided to a pipeline.
	Outputs map[string]io.Closer

	// ReceivePipelineCancellation determines whether the step will receive pipeline cancellation
	// signals via the context passed to WorkFunc.
	//
	// Steps in a pipeline usually return in response to their input channel closing, not the pipeline
	// context being cancelled. This allows for a cascading shutdown of the steps in the pipeline.
	//
	// However, not all steps have an input channel, these steps will want to listen to the pipeline
	// cancellation signal and shutdown when it is cancelled.
	//
	// Note: steps might still receive cancellation signals for other reasons, especially if they
	// are not managed directly by a pipeline. Steps should still honor such cancellation signals.
	ReceivePipelineCancellation bool

	// Func is the function that will be ran by the pipeline. If Func returns an error, the
	// pipeline will be closed.
	Func func(ctx context.Context) error
}

type PipelineStepError struct {
	StepID string
	Err    error
}

func (e PipelineStepError) Unwrap() error {
	return e.Err
}

func (e PipelineStepError) Error() string {
	return "step " + e.StepID + " failed: " + e.Err.Error()
}

type OutputCloseError struct {
	OutputID string
	Err      error
}

func (e OutputCloseError) Unwrap() error {
	return e.Err
}

func (e OutputCloseError) Error() string {
	return "failed to close output " + e.OutputID + ": " + e.Err.Error()
}

var ErrPipelineClosed = fmt.Errorf("pipeline closed: %w", context.Canceled)

func DropErrPipelineClosed(ctx context.Context, err error) error {
	if err == nil || IsErrPipelineClosed(ctx, err) {
		return nil
	}
	return err
}

func IsErrPipelineClosed(ctx context.Context, err error) bool {
	return errors.Is(err, context.Canceled) && errors.Is(context.Cause(ctx), ErrPipelineClosed)
}

// Pipeline manages a pipeline of workers and any shared channels.
type Pipeline struct {
	gracefulCtx    context.Context
	gracefulCancel context.CancelCauseFunc
	hardCtx        context.Context
	hardCancel     context.CancelCauseFunc
	results        chan error
	stepCount      int
}

// RunPipeline runs a pipeline of steps in the background, or returns an error
// if the steps are invalid.
//
// The caller should always call [Close] on the pipeline when they are done.
func RunPipeline(ctx context.Context, steps ...PipelineStep) (*Pipeline, error) {
	seenSteps := map[string]struct{}{}
	outputs := sharedOutputs{}
	for i, s := range steps {
		if s.ID == "" {
			return nil, fmt.Errorf("worker at index %d has an empty id", i)
		}

		_, ok := seenSteps[s.ID]
		if ok {
			return nil, fmt.Errorf("duplicate step id %s at index %d", s.ID, i)
		}

		if s.Func == nil {
			return nil, fmt.Errorf("step %s at index %d is missing a step function", s.ID, i)
		}

		seenSteps[s.ID] = struct{}{}

		err := outputs.addMany(s.Outputs)
		if err != nil {
			return nil, fmt.Errorf("step %s at index %d has invalid outputs: %w", s.ID, i, err)
		}
	}

	gracefulCtx, gracefulCancel := context.WithCancelCause(ctx)
	// hardCtx will be passed to steps that don't receive pipeline cancellation signals.
	hardCtx, hardCancel := context.WithCancelCause(context.WithoutCancel(gracefulCtx))
	p := &Pipeline{
		gracefulCtx:    gracefulCtx,
		gracefulCancel: gracefulCancel,
		hardCtx:        hardCtx,
		hardCancel:     hardCancel,
		results:        make(chan error),
		stepCount:      len(steps),
	}

	for _, w := range steps {
		go func() {
			var err error
			if w.ReceivePipelineCancellation {
				err = w.Func(gracefulCtx)
			} else {
				err = w.Func(hardCtx)
			}
			if err != nil {
				err = PipelineStepError{
					StepID: w.ID,
					Err:    err,
				}
			}
			// regardless of what happened, mark the outputs for this
			// step as done and potentially close them.
			err = errors.Join(err, outputs.manyDone(w.Outputs))
			// if either the step, or the output handling failed, close the pipeline.
			if err != nil {
				slog.Error("pipeline step failed", "step", w.ID, "error", err.Error())
				gracefulCancel(err)
			}

			slog.Debug("pipeline step shut down", "step", w.ID)
			p.results <- err
		}()
	}

	return p, nil
}

func (p *Pipeline) Close(ctx context.Context) error {
	p.gracefulCancel(ErrPipelineClosed)
	var err error

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			p.hardCancel(context.Cause(ctx))
		case <-done:
			return
		}
	}()

	for i := 0; i < p.stepCount; i++ {
		err = errors.Join(err, <-p.results)
	}
	return err
}

type sharedOutput struct {
	refs   *atomic.Int64
	closer io.Closer
}

type sharedOutputs map[string]sharedOutput

func (c sharedOutputs) addMany(outputs map[string]io.Closer) error {
	for id, closer := range outputs {
		sc, ok := c[id]
		if !ok {
			sc = sharedOutput{
				refs:   &atomic.Int64{},
				closer: closer,
			}
			c[id] = sc
		}

		if sc.closer != closer {
			return fmt.Errorf("output with id %s has different io.Closer values", id)
		}

		sc.refs.Add(1)
	}
	return nil
}

func (c sharedOutputs) manyDone(outputs map[string]io.Closer) error {
	var err error
	for id := range outputs {
		err = errors.Join(err, c.done(id))
	}
	return err
}

func (c sharedOutputs) done(id string) error {
	sc, ok := c[id]
	if !ok {
		return fmt.Errorf("no shared closer for %s", id)
	}

	result := sc.refs.Add(-1)
	if result < 0 {
		return fmt.Errorf("calling done without matching add on shared closer %s", id)
	}

	if result > 0 {
		return nil
	}

	// result == 0
	err := sc.closer.Close()
	if err != nil {
		return OutputCloseError{
			OutputID: id,
			Err:      err,
		}
	}
	return nil
}
