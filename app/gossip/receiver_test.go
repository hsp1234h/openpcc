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

package gossip

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReceiver(t *testing.T) {
	type receiveCall struct {
		chunk []byte
		want  []byte
	}

	tests := map[string][]receiveCall{
		"ok, minimal single-chunk message": {
			{
				chunk: withHeader(0, 0, 1, []byte("a")),
				want:  []byte("a"),
			},
		},
		"ok, multiple minimal single-chunk messages": {
			{
				chunk: withHeader(0, 0, 1, []byte("a")),
				want:  []byte("a"),
			},
			{
				chunk: withHeader(1, 0, 1, []byte("b")),
				want:  []byte("b"),
			},
			{
				chunk: withHeader(2, 0, 1, []byte("c")),
				want:  []byte("c"),
			},
		},
		"ok, single single-chunk message": {
			{
				chunk: withHeader(0, 0, 1, []byte("abcde")),
				want:  []byte("abcde"),
			},
		},
		"ok, duplicate single-chunk message": {
			{
				chunk: withHeader(0, 0, 1, []byte("abcde")),
				want:  []byte("abcde"),
			},
			{
				chunk: withHeader(0, 0, 1, []byte("abcde")),
				want:  nil,
			},
		},
		"ok, single multi-chunk message": {
			{
				chunk: withHeader(0, 0, 0, []byte("a")),
				want:  nil,
			},
			{
				chunk: withHeader(0, 1, 0, []byte("b")),
				want:  nil,
			},
			{
				chunk: withHeader(0, 2, 1, []byte("c")),
				want:  []byte("abc"),
			},
		},
		"ok, single multi-chunk message, inverted order": {
			{
				chunk: withHeader(0, 2, 1, []byte("c")),
				want:  nil,
			},
			{
				chunk: withHeader(0, 1, 0, []byte("b")),
				want:  nil,
			},
			{
				chunk: withHeader(0, 0, 0, []byte("a")),
				want:  []byte("abc"),
			},
		},
		"ok, mix of messages": {
			{
				chunk: withHeader(0, 2, 1, []byte("c")),
				want:  nil,
			},
			{
				chunk: withHeader(1, 0, 1, []byte("12345")),
				want:  []byte("12345"),
			},
			{
				chunk: withHeader(0, 0, 0, []byte("a")),
				want:  nil,
			},
			{
				chunk: withHeader(1, 0, 1, []byte("12345")), // duplicate of message #2
				want:  nil,
			},
			{
				chunk: withHeader(0, 1, 0, []byte("b")),
				want:  []byte("abc"),
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rcv := newReceiver()
			for _, call := range tc {
				got, err := rcv.receiveChunk(call.chunk)
				require.NoError(t, err)
				require.Equal(t, call.want, got)
			}
		})
	}

	failTests := map[string]func() []byte{
		"fail, nil chunk": func() []byte {
			return nil
		},
		"fail, empty chunk": func() []byte {
			return []byte{}
		},
		"fail, header only": func() []byte {
			return make([]byte, headerLen)
		},
		"fail, invalid version": func() []byte {
			data := withHeader(0, 0, 0, []byte("a"))
			data[0] = 2
			return data
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rcv := newReceiver()
			_, err := rcv.receiveChunk(tc())
			require.Error(t, err)
		})
	}

	t.Run("ok, cleanup can cause dropped message", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		rcv := newReceiver()
		rcv.nowFunc = func() time.Time {
			return now
		}

		// add first chunk of a message at "now"
		data, err := rcv.receiveChunk(withHeader(0, 0, 0, []byte("a")))
		require.NoError(t, err)
		require.Empty(t, data)

		// forward time by two milliseconds
		rcv.nowFunc = func() time.Time {
			return now.Add(time.Millisecond * 2)
		}

		// cleanup messages older than a millisecond
		rcv.cleanup(time.Millisecond)

		// add second chunk of a message
		data, err = rcv.receiveChunk(withHeader(0, 1, 1, []byte("b")))
		require.NoError(t, err)
		require.Empty(t, data) // confirm we DONT get a message because of the cleanup.
	})

	t.Run("ok, cleanup can cause duplicate message", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		rcv := newReceiver()
		rcv.nowFunc = func() time.Time {
			return now
		}

		// send a message at "now"
		data, err := rcv.receiveChunk(withHeader(0, 0, 1, []byte("a")))
		require.NoError(t, err)
		require.Equal(t, []byte("a"), data)

		// forward time by two milliseconds
		rcv.nowFunc = func() time.Time {
			return now.Add(time.Millisecond * 2)
		}

		// cleanup messages older than a millisecond
		rcv.cleanup(time.Millisecond)

		// repeat the message
		data, err = rcv.receiveChunk(withHeader(0, 0, 1, []byte("a")))
		require.NoError(t, err)
		require.Equal(t, []byte("a"), data)
	})

	t.Run("ok, check for dataraces", func(t *testing.T) {
		t.Parallel()

		rcv := newReceiver()

		chunks := [][]byte{
			withHeader(0, 0, 0, []byte("a")),
			withHeader(0, 1, 0, []byte("b")),
			withHeader(0, 2, 1, []byte("c")),
		}

		var wg sync.WaitGroup
		wg.Add(len(chunks))
		for _, chunk := range chunks {
			go func(chnk []byte) {
				data, err := rcv.receiveChunk(chnk)
				require.NoError(t, err)
				if len(data) > 0 {
					require.Equal(t, []byte("abc"), data)
				}
				wg.Done()
			}(chunk)
		}

		wg.Add(1)
		go func() {
			rcv.cleanup(time.Hour)
			wg.Done()
		}()

		wg.Wait()
	})

	t.Run("ok, receiver copies chunk", func(t *testing.T) {
		t.Parallel()

		rcv := newReceiver()

		chnk1 := withHeader(0, 0, 0, []byte("a"))
		chnk2 := withHeader(0, 1, 1, []byte("b"))

		msg, err := rcv.receiveChunk(chnk1)
		require.NoError(t, err)
		require.Empty(t, msg)

		// modify chunk 1
		chnk1[1]++
		chnk1[headerLen]++

		msg, err = rcv.receiveChunk(chnk2)
		require.NoError(t, err)
		require.Equal(t, []byte("ab"), msg)
	})
}
