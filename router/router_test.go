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

package router_test

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/router"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/router/api"
	"github.com/openpcc/openpcc/router/health"
	"github.com/openpcc/openpcc/router/state"
	"github.com/openpcc/openpcc/tags"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/require"
)

func TestRouterQueryComputeManifests(t *testing.T) {
	newNodeEventWithTags := func(t *testing.T, id uuid.UUID, tgs []string) *agent.NodeEvent {
		ev := newNodeEvent(t, id, "http://127.0.0.1")
		ev.Heartbeat.RoutingInfo.Tags = test.Must(tags.FromSlice(tgs))
		return ev
	}

	tests := map[string]struct {
		nodes []*agent.NodeEvent
		req   *api.ComputeManifestRequest
		want  func(t *testing.T, got api.ComputeManifestList)
	}{
		"ok, empty routing set": {
			nodes: []*agent.NodeEvent{},
			req: &api.ComputeManifestRequest{
				Tags:  tags.Tags{}, // matches all tags
				Limit: 10,
			},
			want: func(t *testing.T, got api.ComputeManifestList) {
				require.Nil(t, got)
			},
		},
		"ok, no matching nodes": {
			nodes: []*agent.NodeEvent{
				newNodeEventWithTags(t, test.DeterministicV7UUID(0), []string{"b"}),
			},
			req: &api.ComputeManifestRequest{
				Tags:  test.Must(tags.FromSlice([]string{"a"})), // matches all tags
				Limit: 10,
			},
			want: func(t *testing.T, got api.ComputeManifestList) {
				require.Nil(t, got)
			},
		},
		"ok, matches single node": {
			nodes: []*agent.NodeEvent{
				newNodeEventWithTags(t, test.DeterministicV7UUID(0), []string{"a"}),
			},
			req: &api.ComputeManifestRequest{
				Tags:  test.Must(tags.FromSlice([]string{"a"})), // matches all tags
				Limit: 10,
			},
			want: func(t *testing.T, got api.ComputeManifestList) {
				require.Equal(t, got, api.ComputeManifestList{
					{
						ID:       test.DeterministicV7UUID(0),
						Tags:     test.Must(tags.FromSlice([]string{"a"})),
						Evidence: newEvidenceList(test.DeterministicV7UUID(0)),
					},
				})
			},
		},
		"ok, matches all nodes": {
			nodes: []*agent.NodeEvent{
				newNodeEventWithTags(t, test.DeterministicV7UUID(0), []string{"a"}),
				newNodeEventWithTags(t, test.DeterministicV7UUID(1), []string{"a", "b"}),
				newNodeEventWithTags(t, test.DeterministicV7UUID(2), []string{"a", "b", "c"}),
			},
			req: &api.ComputeManifestRequest{
				Tags:  test.Must(tags.FromSlice([]string{"a"})), // matches all tags
				Limit: 10,
			},
			want: func(t *testing.T, got api.ComputeManifestList) {
				// don't care about the order of the results.
				require.ElementsMatch(t, got, api.ComputeManifestList{
					{
						ID:       test.DeterministicV7UUID(0),
						Tags:     test.Must(tags.FromSlice([]string{"a"})),
						Evidence: newEvidenceList(test.DeterministicV7UUID(0)),
					},
					{
						ID:       test.DeterministicV7UUID(1),
						Tags:     test.Must(tags.FromSlice([]string{"a", "b"})),
						Evidence: newEvidenceList(test.DeterministicV7UUID(1)),
					},
					{
						ID:       test.DeterministicV7UUID(2),
						Tags:     test.Must(tags.FromSlice([]string{"a", "b", "c"})),
						Evidence: newEvidenceList(test.DeterministicV7UUID(2)),
					},
				})
			},
		},
		"ok, matches some nodes": {
			nodes: []*agent.NodeEvent{
				newNodeEventWithTags(t, test.DeterministicV7UUID(0), []string{"a"}),
				newNodeEventWithTags(t, test.DeterministicV7UUID(1), []string{"a", "b"}),
				newNodeEventWithTags(t, test.DeterministicV7UUID(2), []string{"a", "b", "c"}),
			},
			req: &api.ComputeManifestRequest{
				Tags:  test.Must(tags.FromSlice([]string{"b"})), // matches some tags
				Limit: 10,
			},
			want: func(t *testing.T, got api.ComputeManifestList) {
				// don't care about the order of the results.
				require.ElementsMatch(t, got, api.ComputeManifestList{
					{
						ID:       test.DeterministicV7UUID(1),
						Tags:     test.Must(tags.FromSlice([]string{"a", "b"})),
						Evidence: newEvidenceList(test.DeterministicV7UUID(1)),
					},
					{
						ID:       test.DeterministicV7UUID(2),
						Tags:     test.Must(tags.FromSlice([]string{"a", "b", "c"})),
						Evidence: newEvidenceList(test.DeterministicV7UUID(2)),
					},
				})
			},
		},
		"ok, limit is respected": {
			nodes: []*agent.NodeEvent{
				newNodeEventWithTags(t, test.DeterministicV7UUID(0), []string{"a"}),
				newNodeEventWithTags(t, test.DeterministicV7UUID(1), []string{"a", "b"}),
				newNodeEventWithTags(t, test.DeterministicV7UUID(2), []string{"a", "b", "c"}),
			},
			req: &api.ComputeManifestRequest{
				Tags:  test.Must(tags.FromSlice([]string{"b"})), // matches some tags
				Limit: 1,
			},
			want: func(t *testing.T, got api.ComputeManifestList) {
				// don't care about the order of the results.
				require.Len(t, got, 1)
				require.Contains(t, api.ComputeManifestList{
					{
						ID:       test.DeterministicV7UUID(1),
						Tags:     test.Must(tags.FromSlice([]string{"a", "b"})),
						Evidence: newEvidenceList(test.DeterministicV7UUID(1)),
					},
					{
						ID:       test.DeterministicV7UUID(2),
						Tags:     test.Must(tags.FromSlice([]string{"a", "b", "c"})),
						Evidence: newEvidenceList(test.DeterministicV7UUID(2)),
					},
				}, got[0])
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rtr := router.New(uuidv7.MustNew(), &relaxedNodeEvaluator{})
			for _, node := range tc.nodes {
				rtr.AddNodeEvent(t.Context(), node)
			}

			got := rtr.QueryComputeManifests(t.Context(), tc.req)
			tc.want(t, got)
		})
	}

	t.Run("ok, returns clones", func(t *testing.T) {
		rtr := router.New(uuidv7.MustNew(), &relaxedNodeEvaluator{})
		rtr.AddNodeEvent(t.Context(), newNodeEventWithTags(t, test.DeterministicV7UUID(0), []string{"a"}))

		got1 := rtr.QueryComputeManifests(t.Context(), &api.ComputeManifestRequest{
			Tags:  test.Must(tags.FromSlice([]string{"a"})),
			Limit: 1,
		})
		require.Len(t, got1, 1)

		got2 := rtr.QueryComputeManifests(t.Context(), &api.ComputeManifestRequest{
			Tags:  test.Must(tags.FromSlice([]string{"a"})),
			Limit: 1,
		})
		require.Len(t, got2, 1)

		require.Equal(t, got1, got2)

		// check if tags are cloned.
		err := got1[0].Tags.AddTag("b")
		require.NoError(t, err)
		require.NotEqual(t, got1[0].Tags, got2[0].Tags)

		// check if evidence is cloned
		got1[0].Evidence[0].Data[0]++
		require.NotEqual(t, got1[0].Evidence, got2[0].Evidence)
	})
}

func newNodeEvent(_ *testing.T, id uuid.UUID, baseURL string) *agent.NodeEvent {
	return &agent.NodeEvent{
		EventIndex: 0,
		NodeID:     id,
		Timestamp:  time.Now().UTC().Round(0),
		Heartbeat: &agent.Heartbeat{
			RoutingInfo: &agent.RoutingInfo{
				URL:            *test.Must(url.Parse(baseURL + "/target-endpoint")),
				HealthcheckURL: *test.Must(url.Parse(baseURL + "/_health")),
				Tags: tags.Tags{
					"v1.0.0":            {},
					"model=llama3.2:1b": {},
				},
				Evidence: newEvidenceList(id),
			},
		},
	}
}

func newEvidenceList(id uuid.UUID) ev.SignedEvidenceList {
	return ev.SignedEvidenceList{
		&ev.SignedEvidencePiece{
			Type:      ev.EventLog,
			Data:      id[:],
			Signature: id[:],
		},
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

type relaxedNodeEvaluator struct{}

func (e *relaxedNodeEvaluator) Evaluate(agent *state.Agent, health *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
	nextCheck := time.Hour
	if agent != nil {
		if agent.ShutdownAt != nil {
			return nil, nil
		}
		return agent.RoutingInfo, &nextCheck
	}
	return nil, &nextCheck
}

//nolint:unparam
func timestamp(minutes int) time.Time {
	baseTime := time.Date(2024, 2, 18, 12, 0, 0, 0, time.UTC)
	return baseTime.Add(time.Duration(minutes) * time.Minute)
}

//nolint:unparam
func healthcheck(minutes int) health.Check {
	return health.Check{
		NodeID:         uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
		URL:            *test.Must(url.Parse("http://localhost/test")),
		Timestamp:      timestamp(minutes),
		Latency:        time.Second,
		HTTPStatusCode: http.StatusOK,
	}
}
