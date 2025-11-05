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

package gossip_test

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/openpcc/openpcc/app/gossip"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApp(t *testing.T) {
	messageTests := map[string]func() []byte{
		// empty messages don't result in broadcasts for now.
		"ok, short message": func() []byte {
			return []byte("abc")
		},
		"ok, long message": func() []byte {
			return bytes.Repeat([]byte("a"), 4096)
		},
	}
	for name, tc := range messageTests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec1 := newRecorder()
			app1, addr1, shutdown1 := runGossipApp(t, nil, gossip.WithMessageHandler(rec1))
			defer shutdown1(t)

			rec2 := newRecorder()
			app2, _, shutdown2 := runGossipApp(t, []string{addr1}, gossip.WithMessageHandler(rec2))
			defer shutdown2(t)

			// broadcast the message from app2 to app1.
			app2.BroadcastMessage(tc())

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				require.Equal(collect, tc(), rec1.lastMessage())
			}, 1*time.Second, 10*time.Millisecond)

			// broadcast the reversed message from app1 to app2
			app1.BroadcastMessage(reverseBytes(tc()))
			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				require.Equal(collect, reverseBytes(tc()), rec2.lastMessage())
			}, 1*time.Second, 10*time.Millisecond)

			// ensure both recorders only received a single message.
			require.Equal(t, 1, rec1.handleCalls())
			require.Equal(t, 1, rec2.handleCalls())
		})
	}

	stateTests := map[string]func() []byte{
		"ok, empty state": func() []byte {
			return nil
		},
		"ok, short state": func() []byte {
			return []byte("a")
		},
		"ok, long state": func() []byte {
			return bytes.Repeat([]byte("a"), 4096)
		},
	}
	for name, tc := range stateTests {
		t.Run(name+", from older app to newer app", func(t *testing.T) {
			t.Parallel()

			rec1 := newRecorder()
			_, addr1, shutdown1 := runGossipApp(
				t,
				nil,
				gossip.WithStateHandler(rec1),
				gossip.WithStateReader(newReader(tc())),
			)
			defer shutdown1(t)

			rec2 := newRecorder()
			_, _, shutdown2 := runGossipApp(
				t,
				[]string{addr1},
				gossip.WithStateHandler(rec2),
			)
			defer shutdown2(t)

			// eventually the state should reach app2
			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				require.Equal(collect, tc(), rec2.lastState())
			}, 1*time.Second, 10*time.Millisecond)

			// since app2 doesn't broadcast state or events,
			// nothing should reach app1.
			require.Equal(t, 0, rec1.handleCalls())
			// app2 could have received more than 1 state handle call by now.
			require.GreaterOrEqual(t, 1, rec2.handleCalls())
		})
		t.Run(name+", from newer app to older app", func(t *testing.T) {
			t.Parallel()

			rec1 := newRecorder()
			_, addr1, shutdown1 := runGossipApp(
				t,
				nil,
				gossip.WithStateHandler(rec1),
			)
			defer shutdown1(t)

			rec2 := newRecorder()
			_, _, shutdown2 := runGossipApp(
				t,
				[]string{addr1},
				gossip.WithStateHandler(rec2),
				gossip.WithStateReader(newReader(tc())),
			)
			defer shutdown2(t)

			// eventually the state should reach app1
			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				require.Equal(collect, tc(), rec1.lastState())
			}, 1*time.Second, 10*time.Millisecond)

			// since app1 doesn't broadcast state or events,
			// nothing should reach app2.
			require.Equal(t, 0, rec2.handleCalls())
			// app1 could have received more than 1 state handle call by now.
			require.GreaterOrEqual(t, 1, rec1.handleCalls())
		})
	}

	t.Run("ok, joins, app1 leaves", func(t *testing.T) {
		t.Parallel()

		rec1 := newRecorder()
		app1, addr1, shutdown1 := runGossipApp(
			t,
			nil,
			gossip.WithNodeHandler(rec1),
			// app 1 has no meta data
		)
		defer shutdown1(t)

		// ensure app1 didn't receive any joins or leaves for itself.
		require.Equal(t, 0, rec1.handleCalls())

		rec2 := newRecorder()
		app2, _, shutdown2 := runGossipApp(
			t,
			[]string{addr1},
			gossip.WithNodeHandler(rec2),
			gossip.WithLocalNodeMeta([]byte("app2")),
		)
		defer shutdown2(t)

		// eventually both should have received a join for each other.
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			id, data := rec1.lastNodeJoin()
			require.Equal(collect, app2.LocalNodeID(), id)
			require.Equal(collect, []byte("app2"), data)
			id, data = rec2.lastNodeJoin()
			require.Equal(collect, app1.LocalNodeID(), id)
			require.Equal(collect, []byte(nil), data)
		}, 1*time.Second, 10*time.Millisecond)

		// ensure either only have received the join handle calls.
		require.Equal(t, 1, rec1.handleCalls())
		require.Equal(t, 1, rec2.handleCalls())

		// make app1 leave.
		shutdown1(t)

		// eventually this leave will be handled in rec2
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			id, data := rec2.lastNodeLeave()
			require.Equal(collect, app1.LocalNodeID(), id)
			require.Equal(collect, []byte(nil), data)
		}, 1*time.Second, 10*time.Millisecond)

		// no other handle calls.
		require.Equal(t, 1, rec1.handleCalls())
		require.Equal(t, 2, rec2.handleCalls())
	})

	t.Run("ok, joins, app2 leaves", func(t *testing.T) {
		t.Parallel()

		rec1 := newRecorder()
		app1, addr1, shutdown1 := runGossipApp(
			t,
			nil,
			gossip.WithNodeHandler(rec1),
			// app 1 has no meta data
		)
		defer shutdown1(t)

		// ensure app1 didn't receive any joins or leaves for itself.
		require.Equal(t, 0, rec1.handleCalls())

		rec2 := newRecorder()
		app2, _, shutdown2 := runGossipApp(
			t,
			[]string{addr1},
			gossip.WithNodeHandler(rec2),
			gossip.WithLocalNodeMeta([]byte("app2")),
		)
		defer shutdown2(t)

		// eventually both should have received a join for each other.
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			id, data := rec1.lastNodeJoin()
			require.Equal(collect, app2.LocalNodeID(), id)
			require.Equal(collect, []byte("app2"), data)
			id, data = rec2.lastNodeJoin()
			require.Equal(collect, app1.LocalNodeID(), id)
			require.Equal(collect, []byte(nil), data)
		}, 1*time.Second, 10*time.Millisecond)

		// ensure either only have received the join handle calls.
		require.Equal(t, 1, rec1.handleCalls())
		require.Equal(t, 1, rec2.handleCalls())

		// make app2 leave.
		shutdown2(t)

		// eventually this leave will be handled in rec1
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			id, data := rec1.lastNodeLeave()
			require.Equal(collect, app2.LocalNodeID(), id)
			require.Equal(collect, []byte("app2"), data)
		}, 1*time.Second, 10*time.Millisecond)

		// no other handle calls.
		require.Equal(t, 2, rec1.handleCalls())
		require.Equal(t, 1, rec2.handleCalls())
	})
}

func runGossipApp(t *testing.T, joins []string, opts ...gossip.Option) (*gossip.App, string, func(t *testing.T)) {
	t.Helper()

	port := test.FreePort(t)
	addr := "127.0.0.1"
	cfg := &gossip.Config{
		MemberlistConfig: gossip.MemberlistConfig{
			Profile:       "local",
			BindAddr:      &addr,
			BindPort:      &port,
			AdvertiseAddr: &addr,
			AdvertisePort: &port,
		},
		PeerDiscoveryInterval:  1 * time.Second,
		PeerDiscoveryThreshold: 1,
		MaxPeersToJoin:         1,
		JoinAddrs:              joins,
	}

	nodeAddr := fmt.Sprintf("127.0.0.1:%d", port)

	id, err := uuidv7.New()
	require.NoError(t, err)

	app, err := gossip.NewApp(cfg, id, opts...)
	require.NoError(t, err)

	go func() {
		err := app.Run()
		require.NoError(t, err)
	}()

	cleanup := func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 1*time.Second)
		defer cancel()

		err := app.Shutdown(ctx)
		require.NoError(t, err)
	}

	require.Eventually(t, func() bool {
		return app.IsJoinable()
	}, 1*time.Second, 10*time.Millisecond)

	return app, nodeAddr, cleanup
}

type recorder struct {
	mu *sync.Mutex

	recordings     int
	msg            []byte
	state          []byte
	nodeJoinID     uuid.UUID
	nodeJoinData   []byte
	nodeUpdateID   uuid.UUID
	nodeUpdateData []byte
	nodeLeaveID    uuid.UUID
	nodeLeaveData  []byte
}

func newRecorder() *recorder {
	return &recorder{
		mu: &sync.Mutex{},
	}
}

func (r *recorder) handleCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.recordings
}

func (r *recorder) lastMessage() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.msg)
}

func (r *recorder) lastState() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.state)
}

func (r *recorder) lastNodeJoin() (uuid.UUID, []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nodeJoinID, r.nodeJoinData
}

func (r *recorder) lastNodeLeave() (uuid.UUID, []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nodeLeaveID, r.nodeLeaveData
}

func (r *recorder) HandleMessage(ctx context.Context, msg []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.recordings++
	r.msg = bytes.Clone(msg)
}

func (r *recorder) HandleState(ctx context.Context, state []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.recordings++
	r.state = bytes.Clone(state)
}

func (r *recorder) HandleNodeJoin(ctx context.Context, id uuid.UUID, b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.nodeJoinID = id
	r.nodeJoinData = bytes.Clone(b)
	r.recordings++
}

func (r *recorder) HandleNodeUpdate(ctx context.Context, id uuid.UUID, b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.nodeUpdateID = id
	r.nodeUpdateData = bytes.Clone(b)
	r.recordings++
}

func (r *recorder) HandleNodeLeave(ctx context.Context, id uuid.UUID, b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.nodeLeaveID = id
	r.nodeLeaveData = bytes.Clone(b)
	r.recordings++
}

type reader struct {
	mu *sync.Mutex
	b  []byte
}

func newReader(b []byte) *reader {
	return &reader{
		mu: &sync.Mutex{},
		b:  b,
	}
}

func (r *reader) ReadState(ctx context.Context) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()

	return bytes.Clone(r.b)
}

func (r *reader) ReadLocalNode(limit int) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.b) > limit {
		return bytes.Clone(r.b)[:limit]
	}
	return bytes.Clone(r.b)
}

func reverseBytes(s []byte) []byte {
	s = bytes.Clone(s)
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}
