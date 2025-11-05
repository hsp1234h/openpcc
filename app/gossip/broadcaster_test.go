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
	"encoding/binary"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBroadcaster(t *testing.T) {
	const headerLen = 22

	type call struct {
		overhead int
		limit    int
		want     [][]byte
	}

	tests := map[string]struct {
		msgs  [][]byte
		calls []call
	}{
		"ok, no broadcasts": {
			msgs: nil,
			calls: []call{
				{
					overhead: 1,
					limit:    2,
					want:     nil,
				},
			},
		},
		"ok, empty message, no broadcasts": {
			msgs: [][]byte{{}},
			calls: []call{
				{
					overhead: 1,
					limit:    2,
					want:     nil,
				},
			},
		},
		"ok, nil message, no broadcasts": {
			msgs: [][]byte{nil},
			calls: []call{
				{
					overhead: 1,
					limit:    2,
					want:     nil,
				},
			},
		},
		"ok, single minimal message in single chunk": {
			msgs: [][]byte{
				[]byte("a"),
			},
			calls: []call{
				{
					overhead: 1,
					limit:    headerLen + 1 + 1,
					want: [][]byte{
						withHeader(0, 0, 1, []byte("a")),
					},
				},
				{ // verify empty read after this
					overhead: 1,
					limit:    headerLen + 1 + 1,
					want:     nil,
				},
			},
		},
		"ok, single minimal message in single chunk with remaining capacity": {
			msgs: [][]byte{
				[]byte("a"),
			},
			calls: []call{
				{
					overhead: 1,
					limit:    headerLen + 1 + 1 + 1, // 1 byte of capacity remaining
					want: [][]byte{
						withHeader(0, 0, 1, []byte("a")),
					},
				},
			},
		},
		"ok, single longer message over multiple calls": {
			msgs: [][]byte{
				[]byte("abc"),
			},
			calls: []call{
				{
					overhead: 1,
					limit:    headerLen + 1 + 1,
					want: [][]byte{
						withHeader(0, 0, 0, []byte("a")),
					},
				},
				{
					overhead: 1,
					limit:    headerLen + 1 + 1,
					want: [][]byte{
						withHeader(0, 1, 0, []byte("b")),
					},
				},
				{
					overhead: 1,
					limit:    headerLen + 1 + 1,
					want: [][]byte{
						withHeader(0, 2, 1, []byte("c")),
					},
				},
			},
		},
		"ok, single longer message in single chunk": {
			msgs: [][]byte{
				[]byte("abc"),
			},
			calls: []call{
				{
					overhead: 1,
					limit:    headerLen + 3 + 1,
					want: [][]byte{
						withHeader(0, 0, 1, []byte("abc")),
					},
				},
			},
		},
		"ok, multiple minimal messages in one call": {
			msgs: [][]byte{
				[]byte("a"),
				[]byte("b"),
				[]byte("c"),
			},
			calls: []call{
				{
					overhead: 1,
					limit:    (headerLen * 3) + (3 * 1) + (3 * 1),
					want: [][]byte{
						withHeader(0, 0, 1, []byte("a")),
						withHeader(1, 0, 1, []byte("b")),
						withHeader(2, 0, 1, []byte("c")),
					},
				},
			},
		},
		"ok, mix of messages in one call": {
			msgs: [][]byte{
				[]byte("abc"),
				[]byte("d"),
				[]byte("efghij"),
			},
			calls: []call{
				{
					overhead: 3,
					limit:    (headerLen * 3) + (3 * 3) + (3 + 1 + 6),
					want: [][]byte{
						withHeader(0, 0, 1, []byte("abc")),
						withHeader(1, 0, 1, []byte("d")),
						withHeader(2, 0, 1, []byte("efghij")),
					},
				},
			},
		},
		"ok, mix of messages in multiple calls": {
			msgs: [][]byte{
				[]byte("abc"),
				[]byte("d"),
				[]byte("efghij"),
			},
			calls: []call{
				{
					overhead: 3,
					limit:    (headerLen) + 3 + 2,
					want: [][]byte{
						withHeader(0, 0, 0, []byte("ab")),
					},
				},
				{
					overhead: 3,
					limit:    (headerLen * 2) + (3 * 2) + (1 * 2),
					want: [][]byte{
						withHeader(0, 1, 1, []byte("c")),
						withHeader(1, 0, 1, []byte("d")),
					},
				},
				{
					overhead: 3,
					limit:    (headerLen) + 3 + 2,
					want: [][]byte{
						withHeader(2, 0, 0, []byte("ef")),
					},
				},
				{
					overhead: 3,
					limit:    (headerLen) + 3 + 4,
					want: [][]byte{
						withHeader(2, 1, 1, []byte("ghij")),
					},
				},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := newBroadcaster()
			c.idFunc = sequentialIDGen(t)

			for _, msg := range tc.msgs {
				c.message(msg)
			}

			for _, call := range tc.calls {
				got, err := c.chunks(call.overhead, call.limit)
				require.NoError(t, err)
				require.Equal(t, call.want, got)
			}
		})
	}

	t.Run("ok, check for dataraces", func(t *testing.T) {
		c := newBroadcaster()

		msgs := [][]byte{
			[]byte("abc"),
			[]byte("defghi"),
			[]byte("jklmn"),
		}

		var wg sync.WaitGroup
		wg.Add(len(msgs))
		for _, msg := range msgs {
			go func(m []byte) {
				c.message(m)
				wg.Done()
			}(msg)
		}

		reads := 10
		wg.Add(reads)
		for range reads {
			go func() {
				_, err := c.chunks(1, headerLen+3)
				require.NoError(t, err)
				wg.Done()
			}()
		}

		wg.Wait()
	})
}

func withHeader(id uint64, chunkIndex uint32, final byte, data []byte) []byte {
	header := make([]byte, 1+16+4+1)
	header[0] = 1 // version byte

	idB := getUintID(id)
	copy(header[1:17], idB[:])

	binary.BigEndian.PutUint32(header[17:21], chunkIndex)
	header[21] = final

	return append(header, data...)
}

func sequentialIDGen(t *testing.T) func([]byte) error {
	id := uint64(0)

	return func(b []byte) error {
		out := getUintID(id)
		n := copy(b, out[:])
		require.Equal(t, 16, n)
		id++
		return nil
	}
}

func getUintID(id uint64) [16]byte {
	out := make([]byte, 16)
	binary.BigEndian.PutUint64(out[8:], id)
	return [16]byte(out)
}
