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

package delay_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openpcc/openpcc/delay"
	"github.com/stretchr/testify/require"
)

func TestPoolAdd(t *testing.T) {
	p := delay.NewPool[string](0)
	defer p.CloseImmediate()

	addB := time.Now()
	require.NoError(t, p.Add(t.Context(), "b", time.Millisecond*11))

	addA := time.Now()
	require.NoError(t, p.Add(t.Context(), "a", time.Millisecond*6))

	addC := time.Now()
	require.NoError(t, p.Add(t.Context(), "c", time.Millisecond*16))

	requireDelayedOutput(t, p, addA, delay.Delayed[string]{time.Millisecond * 6, "a"})
	requireDelayedOutput(t, p, addB, delay.Delayed[string]{time.Millisecond * 11, "b"})
	requireDelayedOutput(t, p, addC, delay.Delayed[string]{time.Millisecond * 16, "c"})
}

func TestPoolAddConcurrently(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		p := delay.NewPool[string](1)
		defer p.CloseImmediate()

		start := time.Now()

		require.NoError(t, p.Add(t.Context(), "a", time.Millisecond*6))

		go func() {
			require.NoError(t, p.Add(t.Context(), "b", time.Millisecond*10))
		}()

		// do two reads
		wantOneOf := []delay.Delayed[string]{
			{time.Millisecond * 6, "a"},
			{time.Millisecond * 10, "b"},
		}
		got1, ok := <-p.Output()
		require.True(t, ok)
		require.Contains(t, wantOneOf, got1)
		got2, ok := <-p.Output()
		require.True(t, ok)
		require.Contains(t, wantOneOf, got2)
		require.NotEqual(t, got1, got2)

		took := time.Since(start)
		require.GreaterOrEqual(t, took, time.Millisecond*10)
	})
}

func TestPoolAddBlocksDueToCapacity(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		p := delay.NewPool[string](1)
		defer p.CloseImmediate()

		start := time.Now()

		require.NoError(t, p.Add(t.Context(), "a", time.Millisecond*6))

		go func() {
			// should block until a is read from output.
			require.NoError(t, p.Add(t.Context(), "b", time.Millisecond*10))
		}()

		// read a from output
		requireDelayedOutput(t, p, start, delay.Delayed[string]{time.Millisecond * 6, "a"})
		// then read b from output
		requireDelayedOutput(t, p, start, delay.Delayed[string]{time.Millisecond * 10, "b"})

		took := time.Since(start)
		require.GreaterOrEqual(t, time.Millisecond*16, took)
	})

	t.Run("fail, context cancelled", func(t *testing.T) {
		p := delay.NewPool[string](1)
		defer p.CloseImmediate()

		require.NoError(t, p.Add(t.Context(), "a", time.Second*10))

		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error)
		go func() {
			// will block until a is read from output.
			result <- p.Add(ctx, "b", time.Millisecond*10)
		}()

		// give the goroutine a moment to start.
		time.Sleep(time.Millisecond * 10)
		cancel()

		require.ErrorIs(t, context.Canceled, <-result)
	})
}

func TestPoolClose(t *testing.T) {
	t.Run("ok, empty pool", func(t *testing.T) {
		p := delay.NewPool[string](0)
		p.Close()

		// verify output channel is closed.
		_, ok := <-p.Output()
		require.False(t, ok)
	})

	t.Run("ok, non-empty pool blocks until output is drained", func(t *testing.T) {
		p := delay.NewPool[string](0)
		start := time.Now()
		p.Add(t.Context(), "a", time.Millisecond*6)

		wg := &sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			requireDelayedOutput(t, p, start, delay.Delayed[string]{time.Millisecond * 6, "a"})
		}()

		p.Close()
		dur := time.Since(start)
		require.GreaterOrEqual(t, dur, 6*time.Millisecond)

		wg.Wait()

		// verify output channel is closed.
		_, ok := <-p.Output()
		require.False(t, ok)
	})
}

func TestPoolCloseImmediate(t *testing.T) {
	t.Run("ok, empty pool", func(t *testing.T) {
		p := delay.NewPool[string](0)
		got := p.CloseImmediate()
		require.Len(t, got, 0)

		// verify output channel is closed.
		_, ok := <-p.Output()
		require.False(t, ok)
	})

	t.Run("ok, non-empty pool", func(t *testing.T) {
		start := time.Now()
		p := delay.NewPool[string](0)
		require.NoError(t, p.Add(t.Context(), "b", time.Second*11))
		require.NoError(t, p.Add(t.Context(), "a", time.Second*6))
		require.NoError(t, p.Add(t.Context(), "c", time.Second*16))

		result := p.CloseImmediate()
		dur := time.Since(start)
		// make sure we spend less time than the shortest delay. We could tighten,
		// this, but the GH runners can be pretty flaky with these kinds of tests,
		// so we're lenient.
		require.Less(t, dur, time.Second*5)
		require.Equal(t, []string{"a", "b", "c"}, result)
	})
}

func requireDelayedOutput(t *testing.T, p *delay.Pool[string], start time.Time, want delay.Delayed[string]) {
	result, ok := <-p.Output()
	got := time.Now()
	require.True(t, ok)
	require.Equal(t, want, result)
	require.GreaterOrEqual(t, got.Sub(start), result.Delay)
}
