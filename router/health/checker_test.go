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

package health_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/openpcc/openpcc/httpfmt"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/router/health"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	timeBetween = 500 * time.Millisecond
	timeout     = 100 * time.Millisecond
)

func TestCheckerRun(t *testing.T) {
	nodeID1, healthURL1 := runNodeWhile(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	nodeID2, healthURL2 := runNodeWhile(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	got := make(map[uuid.UUID]int)
	var mu sync.Mutex
	c := health.NewChecker(t.Context(), checkerConfig(), &store{
		queryFunc: func(ctx context.Context) (map[uuid.UUID]url.URL, int) {
			return map[uuid.UUID]url.URL{
				nodeID1: healthURL1,
				nodeID2: healthURL2,
			}, 2
		},
		addFunc: func(ctx context.Context, c health.Check) {
			mu.Lock()
			defer mu.Unlock()

			got[c.NodeID]++
		},
	})

	done := make(chan struct{})
	go func() {
		err := c.Run()
		require.NoError(t, err)
		close(done)
	}()

	// eventually we should have healthchecks for both nodes
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		mu.Lock()
		defer mu.Unlock()

		assert.GreaterOrEqual(collect, got[nodeID1], 5)
		assert.GreaterOrEqual(collect, got[nodeID2], 5)
		assert.Len(collect, got, 2)
	}, 5*time.Second, 10*time.Millisecond)

	err := c.Shutdown(t.Context())
	require.NoError(t, err)
	<-done
}

func TestCheckerCheckHealth(t *testing.T) {
	statusCodes := []int{
		http.StatusOK,
		http.StatusCreated,
		http.StatusBadRequest,
		http.StatusInternalServerError,
	}

	for _, code := range statusCodes {
		name := fmt.Sprintf("ok, status %d", code)
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			nodeID, healthURL := runNodeWhile(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			})

			c := health.NewChecker(t.Context(), checkerConfig(), &store{})

			got, err := c.CheckHealth(t.Context(), nodeID, healthURL)
			require.NoError(t, err)

			require.Equal(t, nodeID, got.NodeID)
			require.Equal(t, healthURL, got.URL)
			require.Equal(t, 0, got.Retries)
			require.Equal(t, code, got.HTTPStatusCode)
			require.Equal(t, "", got.ErrorMessage)

			// check time information
			requireRecentTimestamp(t, got.Timestamp)
			requireMaxLatencyAround(t, got.Latency, timeout)
		})
	}

	t.Run("ok, target is offline", func(t *testing.T) {
		t.Parallel()

		nodeID, healthURL, cancel := runNodeWithCancel(t, func(w http.ResponseWriter, r *http.Request) {
			require.Fail(t, "unexpected call")
		})

		// take node offline
		cancel(t)

		c := health.NewChecker(t.Context(), checkerConfig(), &store{})

		got, err := c.CheckHealth(t.Context(), nodeID, healthURL)
		require.NoError(t, err)

		// verify healthcheck
		require.Equal(t, nodeID, got.NodeID)
		require.Equal(t, 0, got.Retries)
		require.Equal(t, healthURL, got.URL)
		require.Equal(t, 0, got.HTTPStatusCode)
		require.Contains(t, got.ErrorMessage, "connect: connection refused")

		// check time information
		requireRecentTimestamp(t, got.Timestamp)
		requireMaxLatencyAround(t, got.Latency, timeout)
	})

	t.Run("ok, target is too slow", func(t *testing.T) {
		// flaking in May 2025
		t.Skip("https://linear.app/confident/issue/CS-763/testcheckercheckhealth-flaky-test")

		t.Parallel()

		nodeID, healthURL := runNodeWhile(t, func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(timeout * 2)
			w.Write([]byte("OK"))
		})

		c := health.NewChecker(t.Context(), checkerConfig(), &store{})

		got, err := c.CheckHealth(t.Context(), nodeID, healthURL)
		require.NoError(t, err)

		// verify healthcheck
		require.Equal(t, nodeID, got.NodeID)
		require.Equal(t, 0, got.Retries)
		require.Equal(t, healthURL, got.URL)
		require.Equal(t, 0, got.HTTPStatusCode)
		require.Contains(t, got.ErrorMessage, "Client.Timeout exceeded")

		// check time information
		requireRecentTimestamp(t, got.Timestamp)
		requireMaxLatencyAround(t, got.Latency, timeout)
	})

	t.Run("ok, succeeds on final retry", func(t *testing.T) {
		t.Parallel()

		var mu sync.Mutex
		attempt := 0
		nodeID, healthURL := runNodeWhile(t, func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()

			if attempt < 2 {
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusOK)
			}
			attempt++
		})

		cfg := checkerConfig()
		cfg.Retries = 3

		c := health.NewChecker(t.Context(), cfg, &store{})
		got, err := c.CheckHealth(t.Context(), nodeID, healthURL)
		require.NoError(t, err)

		mu.Lock()
		defer mu.Unlock()
		require.Equal(t, nodeID, got.NodeID)
		require.Equal(t, healthURL, got.URL)
		require.Equal(t, http.StatusOK, got.HTTPStatusCode)
		require.Equal(t, "", got.ErrorMessage)

		// check time information
		requireRecentTimestamp(t, got.Timestamp)
		requireMaxLatencyAround(t, got.Latency, timeout)
	})

	t.Run("ok, parses error message from JSON endpoint", func(t *testing.T) {
		t.Parallel()

		const want = "hello world!"
		nodeID, healthURL := runNodeWhile(t, func(w http.ResponseWriter, r *http.Request) {
			httpfmt.JSONBadRequest(w, r, want)
		})

		c := health.NewChecker(t.Context(), checkerConfig(), &store{})

		got, err := c.CheckHealth(t.Context(), nodeID, healthURL)
		require.NoError(t, err)

		require.Equal(t, nodeID, got.NodeID)
		require.Equal(t, healthURL, got.URL)
		require.Equal(t, 0, got.Retries)
		require.Equal(t, http.StatusBadRequest, got.HTTPStatusCode)
		require.Equal(t, want, got.ErrorMessage)

		// check time information
		requireRecentTimestamp(t, got.Timestamp)
		requireMaxLatencyAround(t, got.Latency, timeout)
	})

	t.Run("ok, parses error message from binary endpoint", func(t *testing.T) {
		t.Parallel()

		const want = "hello world!"
		nodeID, healthURL := runNodeWhile(t, func(w http.ResponseWriter, r *http.Request) {
			httpfmt.BinaryBadRequest(w, r, want)
		})

		c := health.NewChecker(t.Context(), checkerConfig(), &store{})

		got, err := c.CheckHealth(t.Context(), nodeID, healthURL)
		require.NoError(t, err)

		require.Equal(t, nodeID, got.NodeID)
		require.Equal(t, healthURL, got.URL)
		require.Equal(t, 0, got.Retries)
		require.Equal(t, http.StatusBadRequest, got.HTTPStatusCode)
		require.Equal(t, want, got.ErrorMessage)

		// check time information
		requireRecentTimestamp(t, got.Timestamp)
		requireMaxLatencyAround(t, got.Latency, timeout)
	})
}

func runNodeWithCancel(t *testing.T, handler http.HandlerFunc) (uuid.UUID, url.URL, func(t *testing.T)) {
	t.Helper()

	server := httptest.NewServer(handler)
	cancel := func(t *testing.T) {
		server.Close()
	}

	healthURL := server.URL + "/_health"

	return test.Must(uuid.NewV7()), *test.Must(url.Parse(healthURL)), cancel
}

func runNodeWhile(t *testing.T, handler http.HandlerFunc) (uuid.UUID, url.URL) {
	t.Helper()

	id, healthURL, cancel := runNodeWithCancel(t, handler)

	t.Cleanup(func() {
		cancel(t)
	})

	return id, healthURL
}

type store struct {
	queryFunc func(ctx context.Context) (map[uuid.UUID]url.URL, int)
	addFunc   func(ctx context.Context, c health.Check)
}

func (s *store) QueryHealthcheckTargets(ctx context.Context) (map[uuid.UUID]url.URL, int) {
	if s.queryFunc != nil {
		return s.queryFunc(ctx)
	}
	return nil, 0
}

func (s *store) AddHealthcheck(ctx context.Context, c health.Check) {
	if s.addFunc != nil {
		s.addFunc(ctx, c)
	}
}

func checkerConfig() *health.CheckerConfig {
	cfg := health.DefaultCheckerConfig()
	cfg.Interval = timeBetween
	cfg.RequestTimeout = 100 * time.Millisecond
	cfg.Retries = 1
	return cfg
}

func requireRecentTimestamp(t *testing.T, ts time.Time) {
	t.Helper()

	since := time.Since(ts)
	require.Less(t, since.Abs().Milliseconds(), int64(1000)) // check if timestamp is recent
}

//nolint:unparam // triggered on want, but its clearer with it as a parameter.
func requireMaxLatencyAround(t *testing.T, got time.Duration, want time.Duration) {
	t.Helper()

	if got.Milliseconds() < want.Milliseconds() {
		return
	}

	// allow 15% over wanted latency
	maxAllowed := want * 150 / 100
	if got > maxAllowed {
		t.Errorf("latency too high, got %v, want around %v (max allowed %v)", got, want, maxAllowed)
	}
}
