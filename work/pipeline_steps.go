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
	"sync"
)

// SerialStep is a pipeline step that receives an input,
// executes a function with it, then finally sends the result to output.
//
// Inputs and outputs are processed one after the other. The order of outputs
// will match order of Func invocations.
type SerialStep[In, Out any] struct {
	ID     string
	Func   func(ctx context.Context, val In) (Out, error)
	Input  <-chan In
	Output *Channel[Out]
	// RemainingInput is called when the step failed to produce or send an output for an input.
	RemainingInput func(in In, err error)
}

func NewSyncStep[In, Out any](s *SerialStep[In, Out]) PipelineStep {
	MustHaveInput(s.ID, s.Input)
	MustHaveOutput[Out](s.ID, s.Output)
	return PipelineStep{
		ID:      s.ID,
		Outputs: StepOutputs(s.Output),
		Func: func(ctx context.Context) error {
			for {
				in, err := ReceiveInput(ctx, s.Input)
				if err != nil {
					return DropErrInputClosed(err)
				}
				out, err := s.Func(ctx, in)
				if err != nil {
					err = fmt.Errorf("func failed: %w", err)
					if s.RemainingInput != nil {
						s.RemainingInput(in, err)
					}
					return err
				}

				err = s.Output.Send(ctx, out)
				if err != nil {
					err = fmt.Errorf("failed to send output: %w", err)
					if s.RemainingInput != nil {
						s.RemainingInput(in, err)
					}
					return err
				}
			}
		},
	}
}

type SyncStepOut[T any] struct {
	ID     string
	Func   func(ctx context.Context) (T, error)
	Output *Channel[T]
}

func NewSyncStepOut[T any](s *SyncStepOut[T]) PipelineStep {
	MustHaveOutput[T](s.ID, s.Output)
	return PipelineStep{
		ID:      s.ID,
		Outputs: StepOutputs(s.Output),
		Func: func(ctx context.Context) error {
			for {
				val, err := s.Func(ctx)
				if err != nil {
					return fmt.Errorf("step failed: %w", err)
				}

				err = s.Output.Send(ctx, val)
				if err != nil {
					return fmt.Errorf("failed to send output: %w", err)
				}
			}
		},
	}
}

type SyncStepIn[T any] struct {
	ID    string
	Func  func(ctx context.Context, val T) error
	Input <-chan T
}

func NewSyncStepIn[T any](s *SyncStepIn[T]) PipelineStep {
	MustHaveInput(s.ID, s.Input)
	return PipelineStep{
		ID: s.ID,
		Func: func(ctx context.Context) error {
			for {
				val, err := ReceiveInput(ctx, s.Input)
				if err != nil {
					return DropErrInputClosed(err)
				}

				if s.Func == nil {
					continue
				}

				err = s.Func(ctx, val)
				if err != nil {
					return fmt.Errorf("step failed: %w", err)
				}
			}
		},
	}
}

// ParallelStep receives inputs, runs functions in parallel and sends outputs.
//
// There is no guarantee to the order of outputs.
type ParallelStep[In, Out any] struct {
	ID          string
	Pool        *Pool
	MaxParallel int
	Func        func(ctx context.Context, val In) (Out, error)
	Input       <-chan In
	Output      *Channel[Out]
	// RemainingInput is called when the step failed to produce or send an output for an input.
	RemainingInput func(in In, err error)
}

func NewParallelStep[In, Out any](s *ParallelStep[In, Out]) PipelineStep {
	MustHaveInput(s.ID, s.Input)
	return PipelineStep{
		ID:      s.ID,
		Outputs: StepOutputs(s.Output),
		Func: func(stepCtx context.Context) error {
			type result struct {
				jobID       int64
				remainingIn *In
				output      *Out
				err         error
			}

			// manages a local buffer of results so that workers don't get
			// blocked writing results.
			results := make(chan result, max(0, s.MaxParallel-1))
			slots := make(chan struct{}, max(1, s.MaxParallel))
			ctx, cancelJobs := context.WithCancelCause(stepCtx)
			go func() {
				wg := &sync.WaitGroup{}
				defer func() {
					// wait for open jobs to be done.
					wg.Wait()
					close(results)
				}()
				for i := int64(0); ; i++ {
					// enqueue a slot to claim a job.
					select {
					case slots <- struct{}{}:
					case <-ctx.Done():
						results <- result{jobID: i, err: context.Cause(ctx)}
						return
					}

					// receive an input.
					in, err := ReceiveInput(ctx, s.Input)
					if err != nil {
						results <- result{jobID: i, err: DropErrInputClosed(err)}
						return
					}

					// add the job to the pool.
					wg.Add(1)
					err = s.Pool.AddJob(ctx, JobFunc(func() {
						defer wg.Done()
						val, err := s.Func(ctx, in)
						if err != nil {
							cancelJobs(err)
							results <- result{jobID: i, remainingIn: &in, err: fmt.Errorf("func failed: %w", err)}
							return
						}
						results <- result{jobID: i, output: &val, err: err}
					}))
					if err != nil {
						wg.Done()
						results <- result{jobID: i, remainingIn: &in, err: fmt.Errorf("failed to add job to pool: %w", err)}
						return
					}
				}
			}()

			// collect job results and copy them to the output.
			var err error
			for result := range results {
				if result.err != nil {
					result.err = fmt.Errorf("job %d failed: %w", result.jobID, result.err)
				}

				if s.RemainingInput != nil && result.remainingIn != nil {
					s.RemainingInput(*result.remainingIn, result.err)
				}

				if result.err != nil {
					err = errors.Join(err, result.err)
					select {
					case <-slots:
					default:
					}
					continue
				}

				if result.output != nil && s.Output != nil {
					sendErr := s.Output.Send(stepCtx, *result.output)
					if err != nil {
						err = errors.Join(err, sendErr)
						continue
					}
				}

				// open up a new slot if possible.
				select {
				case <-slots:
				default:
				}
			}

			return err
		},
	}
}
