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

package state_test

import (
	"bytes"
	"net/url"
	"testing"
	"time"

	ev "github.com/openpcc/openpcc/attestation/evidence"
	pb "github.com/openpcc/openpcc/gen/protos/router/cluster"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/router/state"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAgentMergeNodeEvent(t *testing.T) {
	tests := map[string]struct {
		before func() *state.Agent
		event  *agent.NodeEvent
		after  func() *state.Agent // if after is nil, we don't expect any changes
	}{
		"changes, new agent, heartbeat with routing info": {
			before: func() *state.Agent {
				return &state.Agent{}
			},
			event: &agent.NodeEvent{
				EventIndex: 0,
				Timestamp:  timestamp(0),
				Heartbeat: &agent.Heartbeat{
					RoutingInfo: newRoutingInfo(""),
				},
			},
			after: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     0,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        newRoutingInfo(""),
				}
			},
		},
		"changes, new agent, heartbeat with url": {
			before: func() *state.Agent {
				return &state.Agent{}
			},
			event: &agent.NodeEvent{
				EventIndex: 0,
				Timestamp:  timestamp(0),
				Heartbeat: &agent.Heartbeat{
					RoutingInfoURL: test.Must(url.Parse("http://localhost/routing-info")),
				},
			},
			after: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     0,
					LastEventTimestamp: timestamp(0),
				}
			},
		},
		"changes, new agent, shutdown event": {
			before: func() *state.Agent {
				return &state.Agent{}
			},
			event: &agent.NodeEvent{
				EventIndex: 0,
				Timestamp:  timestamp(0),
			},
			after: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     0,
					LastEventTimestamp: timestamp(0),
					ShutdownAt:         timestampPtr(0),
				}
			},
		},
		"no changes, duplicate heartbeat event": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     0,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        newRoutingInfo(""),
				}
			},
			event: &agent.NodeEvent{
				EventIndex: 0,
				Timestamp:  timestamp(0),
				Heartbeat: &agent.Heartbeat{
					RoutingInfo: newRoutingInfo(""),
				},
			},
		},
		"changes, new heartbeat with url, already has routing info": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     0,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        newRoutingInfo(""),
				}
			},
			event: &agent.NodeEvent{
				EventIndex: 1,
				Timestamp:  timestamp(1),
				Heartbeat: &agent.Heartbeat{
					RoutingInfoURL: test.Must(url.Parse("http://localhost/routing-info")),
				},
			},
			after: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     1,                  // updated
					LastEventTimestamp: timestamp(1),       // updated
					RoutingInfo:        newRoutingInfo(""), // remained the same.
				}
			},
		},
		"changes, new heartbeat with url, still missing routing info": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     0,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        nil,
				}
			},
			event: &agent.NodeEvent{
				EventIndex: 1,
				Timestamp:  timestamp(1),
				Heartbeat: &agent.Heartbeat{
					RoutingInfoURL: test.Must(url.Parse("http://localhost/routing-info")),
				},
			},
			after: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     1,            // updated
					LastEventTimestamp: timestamp(1), // updated
					RoutingInfo:        nil,          // remained the same
				}
			},
		},
		"changes, old heartbeat with routing info, did not have routing info": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     1,
					LastEventTimestamp: timestamp(1),
					RoutingInfo:        nil,
				}
			},
			event: &agent.NodeEvent{
				EventIndex: 1,
				Timestamp:  timestamp(0),
				Heartbeat: &agent.Heartbeat{
					RoutingInfo: newRoutingInfo(""),
				},
			},
			after: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     1,                  // remained the same
					LastEventTimestamp: timestamp(1),       // remained the same
					RoutingInfo:        newRoutingInfo(""), // updated
				}
			},
		},
		"no changes, old heartbeat with routing info, already had routing info": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     1,
					LastEventTimestamp: timestamp(1),
					RoutingInfo:        newRoutingInfo(""),
				}
			},
			event: &agent.NodeEvent{
				EventIndex: 1,
				Timestamp:  timestamp(0),
				Heartbeat: &agent.Heartbeat{
					RoutingInfo: newRoutingInfo(""),
				},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			a := tc.before()
			changes := a.MergeNodeEvent(tc.event)
			if tc.after == nil {
				require.False(t, changes)
				require.Equal(t, tc.before(), a)
				return
			}
			require.True(t, changes)
			require.Equal(t, tc.after(), a)
		})
	}
}

func TestAgentMergeState(t *testing.T) {
	tests := map[string]struct {
		before func() *state.Agent
		other  func() *state.Agent
		after  func() *state.Agent // if after is nil, we don't expect any changes to s
	}{
		"no changes, same, both empty": {
			before: func() *state.Agent {
				return &state.Agent{}
			},
			other: func() *state.Agent {
				return &state.Agent{}
			},
		},
		"no changes, same, both have routing info": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        newRoutingInfo(""),
					ShutdownAt:         timestampPtr(0),
				}
			},
			other: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        newRoutingInfo(""),
					ShutdownAt:         timestampPtr(0),
				}
			},
		},
		"no changes, same, both missing routing info": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,
					LastEventTimestamp: timestamp(0),
				}
			},
			other: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,
					LastEventTimestamp: timestamp(0),
				}
			},
		},
		"changes, at same event index, other has missing routing info": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        nil,
				}
			},
			other: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        newRoutingInfo(""),
				}
			},
			after: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,                 // same
					LastEventTimestamp: timestamp(0),       // same
					RoutingInfo:        newRoutingInfo(""), // changed
				}
			},
		},
		"no changes, other at earlier event index, both have routing info": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,
					LastEventTimestamp: timestamp(1),
					RoutingInfo:        newRoutingInfo(""),
				}
			},
			other: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     9,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        newRoutingInfo(""),
				}
			},
		},
		"changes, other at earlier event index, other has missing routing info": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,
					LastEventTimestamp: timestamp(1),
					RoutingInfo:        nil,
				}
			},
			other: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     9,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        newRoutingInfo(""),
				}
			},
			after: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,                 // same
					LastEventTimestamp: timestamp(1),       // same
					RoutingInfo:        newRoutingInfo(""), // changed
				}
			},
		},
		"no changes, other at earlier event index and is missing routing info": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,
					LastEventTimestamp: timestamp(1),
					RoutingInfo:        nil,
				}
			},
			other: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     9,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        nil,
				}
			},
		},
		"changes, other at later event index, both have routing info": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     9,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        newRoutingInfo(""),
				}
			},
			other: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,
					LastEventTimestamp: timestamp(1),
					RoutingInfo:        newRoutingInfo(""),
				}
			},
			after: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,                 // changed
					LastEventTimestamp: timestamp(1),       // changed
					RoutingInfo:        newRoutingInfo(""), // same
				}
			},
		},
		"changes, other at later event index, other missing routing info": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     9,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        newRoutingInfo(""),
				}
			},
			other: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,
					LastEventTimestamp: timestamp(1),
					RoutingInfo:        nil,
				}
			},
			after: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,                 // changed
					LastEventTimestamp: timestamp(1),       // changed
					RoutingInfo:        newRoutingInfo(""), // same
				}
			},
		},
		"changes, other at later event index, other has missing routing info": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     9,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        nil,
				}
			},
			other: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,
					LastEventTimestamp: timestamp(1),
					RoutingInfo:        newRoutingInfo(""),
				}
			},
			after: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,                 // changed
					LastEventTimestamp: timestamp(1),       // changed
					RoutingInfo:        newRoutingInfo(""), // changed
				}
			},
		},
		"changes, other has later event index and shutdown": {
			before: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     9,
					LastEventTimestamp: timestamp(0),
					RoutingInfo:        nil,
				}
			},
			other: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,
					LastEventTimestamp: timestamp(1),
					RoutingInfo:        newRoutingInfo(""),
					ShutdownAt:         timestampPtr(1),
				}
			},
			after: func() *state.Agent {
				return &state.Agent{
					LastEventIndex:     10,                 // changed
					LastEventTimestamp: timestamp(1),       // changed
					RoutingInfo:        newRoutingInfo(""), // changed
					ShutdownAt:         timestampPtr(1),    // changed
				}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			a := tc.before()
			changes := a.MergeState(tc.other())
			if tc.after == nil {
				require.False(t, changes)
				require.Equal(t, tc.before(), a)
				return
			}

			require.True(t, changes)
			require.Equal(t, tc.after(), a)
		})
	}
}

func TestAgentMarshalUnmarshalProto(t *testing.T) {
	tests := map[string]func(pba *pb.AgentState, want *state.Agent){
		"ok, event info only": func(pba *pb.AgentState, want *state.Agent) {
			pba.ClearRoutingInfo()
			want.RoutingInfo = nil
			pba.ClearShutdownAt()
			want.ShutdownAt = nil
		},
		"ok, full state": func(pba *pb.AgentState, want *state.Agent) {},
		"ok, no routing info": func(pba *pb.AgentState, want *state.Agent) {
			pba.ClearRoutingInfo()
			want.RoutingInfo = nil
		},
		"ok, not shutdown": func(pba *pb.AgentState, want *state.Agent) {
			pba.ClearShutdownAt()
			want.ShutdownAt = nil
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			lastEvent := timestamp(0)
			shutdownAt := timestamp(0)

			pbri := newRoutingInfo("").MarshalProto()
			pba := &pb.AgentState{}
			pba.SetLastEventIndex(10)
			pba.SetLastEventTimestamp(timestamppb.New(lastEvent))
			pba.SetRoutingInfo(pbri)
			pba.SetShutdownAt(timestamppb.New(shutdownAt))

			want := &state.Agent{
				LastEventIndex:     10,
				LastEventTimestamp: lastEvent,
				RoutingInfo:        newRoutingInfo(""),
				ShutdownAt:         &shutdownAt,
			}

			tc(pba, want)

			got := &state.Agent{}
			err := got.UnmarshalProto(pba)
			require.NoError(t, err)
			require.Equal(t, want, got)

			// check again but with non-hardcoded pb
			pba = got.MarshalProto()
			err = got.UnmarshalProto(pba)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}

	failTests := map[string]func(pba *pb.AgentState){
		"fail, missing last event index": func(pba *pb.AgentState) {
			pba.ClearLastEventIndex()
		},
		"fail, negative last event index": func(pba *pb.AgentState) {
			pba.SetLastEventIndex(-1)
		},
		"fail, missing last event timestamp": func(pba *pb.AgentState) {
			pba.ClearLastEventTimestamp()
		},
		"fail, invalid routing info": func(pba *pb.AgentState) {
			pba.GetRoutingInfo().SetUrl("://://") // invalid url.
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			lastEvent := timestamp(0)
			shutdownAt := timestamp(0)

			pbri := newRoutingInfo("").MarshalProto()
			pba := &pb.AgentState{}
			pba.SetLastEventIndex(10)
			pba.SetLastEventTimestamp(timestamppb.New(lastEvent))
			pba.SetRoutingInfo(pbri)
			pba.SetShutdownAt(timestamppb.New(shutdownAt))

			tc(pba)

			s := &state.Agent{}
			err := s.UnmarshalProto(pba)
			require.Error(t, err)
		})
	}
}

func newRoutingInfo(postfix string) *agent.RoutingInfo {
	evidence := newEvidenceList()
	return &agent.RoutingInfo{
		URL:            *test.Must(url.Parse("http://localhost/test" + postfix)),
		HealthcheckURL: *test.Must(url.Parse("http://localhost/_health" + postfix)),
		Tags: map[string]struct{}{
			"v1.0.2":            {},
			"llm":               {},
			"model=llama3.2:1b": {},
		},
		Evidence: evidence,
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

func timestamp(minutes int) time.Time {
	baseTime := time.Date(2024, 2, 18, 12, 0, 0, 0, time.UTC)
	return baseTime.Add(time.Duration(minutes) * time.Minute)
}

func timestampPtr(minutes int) *time.Time {
	ts := timestamp(minutes)
	return &ts
}
