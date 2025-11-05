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

package work_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openpcc/openpcc/work"
	"github.com/stretchr/testify/require"
)

func TestPool(t *testing.T) {
	t.Run("ok, all jobs get processed in sequence with 1 worker", func(t *testing.T) {
		p := work.NewPool(3, 1)
		defer p.Close()

		out := make(chan int, 3)
		err := p.AddJob(t.Context(), work.JobFunc(func() {
			out <- 1
		}))
		require.NoError(t, err)
		err = p.AddJob(t.Context(), work.JobFunc(func() {
			out <- 2
		}))
		require.NoError(t, err)
		err = p.AddJob(t.Context(), work.JobFunc(func() {
			out <- 3
		}))
		require.NoError(t, err)
		err = p.AddJob(t.Context(), work.JobFunc(func() {
			close(out)
		}))
		require.NoError(t, err)

		var got []int
		for i := range out {
			got = append(got, i)
		}
		require.Equal(t, []int{1, 2, 3}, got)
	})

	t.Run("ok, blocked add, unblocks when job finishes", func(t *testing.T) {
		p := work.NewPool(0, 1)
		defer p.Close()

		out := make(chan int, 2)
		err := p.AddJob(t.Context(), work.JobFunc(func() {
			// due to 0 queueLen and a single worker, this job will always run to completion
			// before the second job will be ran. Do a sleep to give us the confidence this
			// isn't due to luck.
			time.Sleep(50 * time.Millisecond)
			out <- 1
		}))
		require.NoError(t, err)
		err = p.AddJob(t.Context(), work.JobFunc(func() {
			out <- 2
		}))
		require.NoError(t, err)
		err = p.AddJob(t.Context(), work.JobFunc(func() {
			close(out)
		}))
		require.NoError(t, err)

		var got []int
		for i := range out {
			got = append(got, i)
		}
		require.Equal(t, []int{1, 2}, got)
	})

	t.Run("fail, blocked add, pool is closed", func(t *testing.T) {
		p := work.NewPool(0, 1)
		defer p.Close() // should be fine to close again without issues.

		// add a first job that will run immediately
		out := make(chan int, 2)
		done := make(chan struct{})
		err := p.AddJob(t.Context(), work.JobFunc(func() {
			// this job will run until the other add has returned an error.
			<-done
			out <- 1
			close(out)
		}))
		require.NoError(t, err)

		// while the next AddJob is blocked, we will close the work pool.
		go func() {
			time.Sleep(10 * time.Millisecond)
			p.Close()
		}()

		err = p.AddJob(t.Context(), work.JobFunc(func() {
			out <- 2 // do something so we can make sure it doesn't happen.
		}))
		require.ErrorIs(t, err, work.ErrPoolClosed)

		// stop job 1
		close(done)

		var got []int
		for i := range out {
			got = append(got, i)
		}
		require.Equal(t, []int{1}, got)
	})

	t.Run("fail, blocked add, context cancelled", func(t *testing.T) {
		p := work.NewPool(0, 1)
		defer p.Close() // should be fine to close again without issues.

		// add a first job that will run immediately
		out := make(chan int, 2)
		done := make(chan struct{})
		err := p.AddJob(t.Context(), work.JobFunc(func() {
			// this job will run until the other add has returned an error.
			<-done
			out <- 1
			close(out)
		}))
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(t.Context())
		// while AddJob is blocked, we will close the work pool.
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()

		err = p.AddJob(ctx, work.JobFunc(func() {
			out <- 2 // do something so we can make sure it doesn't happen.
		}))
		require.ErrorIs(t, err, context.Canceled)

		// stop job 1
		close(done)

		var got []int
		for i := range out {
			got = append(got, i)
		}
		require.Equal(t, []int{1}, got)
	})

	t.Run("fail, add to closed pool", func(t *testing.T) {
		p := work.NewPool(0, 1)
		p.Close()

		err := p.AddJob(t.Context(), work.JobFunc(func() {}))
		require.ErrorIs(t, err, work.ErrPoolClosed)
	})

	t.Run("ok, scales up and down", func(t *testing.T) {
		p := work.NewPool(3, 1)
		defer p.Close()

		jobsBegan := &atomic.Int32{}
		// eventually the worker should have spun up and become idle.
		require.Eventually(t, func() bool {
			return p.IdleWorkers() == 1 && p.Workers() == 1
		}, 100*time.Millisecond, 10*time.Millisecond)

		// add a few jobs that will finish when done is called.
		done := make(chan struct{})
		for range 3 {
			err := p.AddJob(t.Context(), work.JobFunc(func() {
				jobsBegan.Add(1)
				<-done
			}))
			require.NoError(t, err)
		}

		defer func() {
			close(done)
		}()

		// eventually the first job should get picked up by the worker.
		require.Eventually(t, func() bool {
			return p.IdleWorkers() == 0 && p.Workers() == 1 && p.OpenJobs() == 2 && jobsBegan.Load() == 1
		}, 100*time.Millisecond, 10*time.Millisecond)

		// scale to 3 workers
		err := p.ScaleWorkers(3)
		require.NoError(t, err)

		// eventually all workers should be busy
		require.Eventually(t, func() bool {
			return p.IdleWorkers() == 0 && p.Workers() == 3 && p.OpenJobs() == 0 && jobsBegan.Load() == 3
		}, 100*time.Millisecond, 10*time.Millisecond)

		// have two jobs finish
		done <- struct{}{}
		done <- struct{}{}

		// eventually two workers should be idle.
		require.Eventually(t, func() bool {
			return p.IdleWorkers() == 2 && p.Workers() == 3 && p.OpenJobs() == 0
		}, 100*time.Millisecond, 10*time.Millisecond)

		// scale down to 1 worker
		err = p.ScaleWorkers(1)
		require.NoError(t, err)

		// eventually only that one worker should remain.
		require.Eventually(t, func() bool {
			return p.IdleWorkers() == 0 && p.Workers() == 1 && p.OpenJobs() == 0
		}, 100*time.Millisecond, 10*time.Millisecond)
	})

	t.Run("fail, can't scale down to less than 1 worker", func(t *testing.T) {
		p := work.NewPool(3, 1)
		defer p.Close()

		// scaling down the last worker should not be possible.
		err := p.ScaleWorkers(0)
		require.Error(t, err)
	})
}
