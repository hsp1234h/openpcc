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

package router

import (
	"bytes"
	"fmt"
	"net/url"
	"testing"

	"github.com/google/uuid"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/tags"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/require"
)

func TestRing(t *testing.T) {
	t.Run("add router", func(t *testing.T) {
		t.Parallel()

		r := newRing()

		r.addRouter(uuidv7.MustNew())

		require.Len(t, r.positions, virtualNodesPerRouter)
		requireSorted(t, r.positions)
		require.Len(t, r.routers, 1)
	})

	t.Run("add same router twice", func(t *testing.T) {
		t.Parallel()

		r := newRing()

		id := uuidv7.MustNew()
		r.addRouter(id)
		r.addRouter(id)

		require.Len(t, r.positions, virtualNodesPerRouter)
		requireSorted(t, r.positions)
		require.Len(t, r.routers, 1)
	})

	t.Run("remove router", func(t *testing.T) {
		t.Parallel()

		r := newRing()

		id1 := uuidv7.MustNew()
		id2 := uuidv7.MustNew()
		r.addRouter(id1)
		r.addRouter(id2)

		require.Len(t, r.positions, virtualNodesPerRouter*2)
		requireSorted(t, r.positions)
		require.Len(t, r.routers, 2)

		r.removeRouter(id1)

		require.Len(t, r.positions, virtualNodesPerRouter)
		requireSorted(t, r.positions)
		require.Len(t, r.routers, 1)

		r.removeRouter(id2)

		require.Len(t, r.positions, 0)
		require.Len(t, r.routers, 0)
	})

	distributeTests := map[string]struct {
		routers      int
		nodes        int
		maxPerRouter int
	}{
		"ok, no routers, no registrations": {
			routers:      0,
			nodes:        0,
			maxPerRouter: 0,
		},
		"ok, router, no registrations": {
			routers:      1,
			nodes:        0,
			maxPerRouter: 0,
		},
		"ok, 1 node over 1 router": {
			routers:      1,
			nodes:        1,
			maxPerRouter: 1,
		},
		"ok, 3 nodes over 1 router": {
			routers:      1,
			nodes:        3,
			maxPerRouter: 3,
		},
		"ok, 1 node over 10 routers": {
			routers:      10,
			nodes:        1,
			maxPerRouter: 1,
		},
		"ok, 10 nodes over 2 routers": {
			routers:      2,
			nodes:        10,
			maxPerRouter: 6,
		},
		"ok, 10 nodes over 10 routers": {
			routers:      10,
			nodes:        10,
			maxPerRouter: 2,
		},
	}

	for name, tc := range distributeTests {
		t.Run(name, func(t *testing.T) {
			r := newRing()

			for i := range tc.routers {
				r.addRouter(makeRouterID(i))
			}

			nodes := make(map[uuid.UUID]url.URL)
			for i := range tc.nodes {
				id, info := makeRoutingInfo(i)
				nodes[id] = info.HealthcheckURL
			}

			seen := make(map[uuid.UUID]int, 0)
			for i := range tc.routers {
				routerID := makeRouterID(i)
				result := r.queryHealthcheckURLs(routerID, nodes)
				require.LessOrEqual(t, len(result), tc.maxPerRouter)

				for id := range result {
					seen[id]++
				}
			}

			// check each node is only assigned to one router
			for id, count := range seen {
				require.Equal(t, 1, count, fmt.Sprintf("node %v was assigned more than once", id))
			}
			require.Equal(t, tc.nodes, len(seen)) // make sure all nodes got assigned
		})
	}
}

func requireSorted(t *testing.T, pos []uint32) {
	t.Helper()

	require.Greater(t, len(pos), 2)

	for i := 1; i < len(pos); i++ {
		require.Less(t, pos[i-1], pos[i])
	}
}

func makeRouterID(i int) uuid.UUID {
	return uuid.MustParse(fmt.Sprintf("00000000-0000-4000-8000-%012d", i))
}

func makeNodeID(i int) uuid.UUID {
	return uuid.MustParse(fmt.Sprintf("10000000-0000-4000-8000-%012d", i))
}

func makeRoutingInfo(i int) (uuid.UUID, *agent.RoutingInfo) {
	return makeNodeID(i), &agent.RoutingInfo{
		URL:            *test.Must(url.Parse("http://example.com")),
		HealthcheckURL: *test.Must(url.Parse("http://localhost/_health")),
		Tags:           test.Must(tags.FromSlice([]string{"llm", "ollama"})),
		Evidence:       newEvidenceList(),
	}
}

func newEvidenceList() ev.SignedEvidenceList {
	return ev.SignedEvidenceList{
		&ev.SignedEvidencePiece{
			Type:      ev.SevSnpReport,
			Data:      bytes.Repeat([]byte("abc"), 2048),
			Signature: []byte("01234567890"),
		},
		&ev.SignedEvidencePiece{
			Type:      ev.SevSnpReport,
			Data:      bytes.Repeat([]byte("def"), 2048),
			Signature: []byte("09876543210"),
		},
	}
}
