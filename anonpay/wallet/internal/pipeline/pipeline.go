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

package pipeline

import (
	"context"

	"github.com/openpcc/openpcc/work"
)

type RootStep struct {
	ID string
	// nolint:revive
	Output *work.Channel[struct{}]
}

func NewRootStep(s *RootStep) work.PipelineStep {
	work.MustHaveOutput[struct{}](s.ID, s.Output)
	return work.PipelineStep{
		ID:                          s.ID,
		Outputs:                     work.StepOutputs(s.Output),
		ReceivePipelineCancellation: true,
		Func: func(ctx context.Context) error {
			<-ctx.Done()
			return work.DropErrPipelineClosed(ctx, context.Cause(ctx))
		},
	}
}

type DropStep[T any] struct {
	ID    string
	Input <-chan T
}

func NewDropStep[T any](s *DropStep[T]) work.PipelineStep {
	return work.PipelineStep{
		ID: s.ID,
		Func: func(ctx context.Context) error {
			for {
				_, err := work.ReceiveInput(ctx, s.Input)
				if err != nil {
					return work.DropErrInputClosed(err)
				}
			}
		},
	}
}

type pipelineSteps []work.PipelineStep

func (s *pipelineSteps) add(steps ...work.PipelineStep) {
	*s = append(*s, steps...)
}
