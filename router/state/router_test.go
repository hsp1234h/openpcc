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
	"testing"

	"github.com/google/uuid"
	pb "github.com/openpcc/openpcc/gen/protos/router/cluster"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/router/health"
	"github.com/openpcc/openpcc/router/state"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRouterMergeNodeEvent(t *testing.T) {
	tests := map[string]struct {
		before func() *state.Router
		event  func() (*agent.NodeEvent, state.RouterChange)
		after  func() *state.Router // if after is nil, we don't expect any changes
	}{
		"changes, first agent": {
			before: func() *state.Router {
				return &state.Router{}
			},
			event: func() (*agent.NodeEvent, state.RouterChange) {
				return &agent.NodeEvent{
						NodeID:     uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
						EventIndex: 0,
						Timestamp:  timestamp(0),
						Heartbeat: &agent.Heartbeat{
							RoutingInfo: newRoutingInfo(""),
						},
					}, state.RouterChange{
						NewAgents: map[uuid.UUID]struct{}{
							uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {},
						},
					}
			},
			after: func() *state.Router {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        newRoutingInfo(""),
						},
					},
				}
			},
		},
		"changes, additional agent": {
			before: func() *state.Router {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        newRoutingInfo("0"),
						},
					},
				}
			},
			event: func() (*agent.NodeEvent, state.RouterChange) {
				return &agent.NodeEvent{
						NodeID:     uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3d"),
						EventIndex: 10,
						Timestamp:  timestamp(1),
						Heartbeat: &agent.Heartbeat{
							RoutingInfo: newRoutingInfo("1"),
						},
					}, state.RouterChange{
						NewAgents: map[uuid.UUID]struct{}{
							uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3d"): {},
						},
					}
			},
			after: func() *state.Router {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        newRoutingInfo("0"),
						},
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3d"): {
							LastEventIndex:     10,
							LastEventTimestamp: timestamp(1),
							RoutingInfo:        newRoutingInfo("1"),
						},
					},
				}
			},
		},
		"no changes, existing agent, event causes no changes": {
			before: func() *state.Router {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        newRoutingInfo(""),
						},
					},
				}
			},
			event: func() (*agent.NodeEvent, state.RouterChange) {
				return &agent.NodeEvent{
					NodeID:     uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
					EventIndex: 0,
					Timestamp:  timestamp(0),
					Heartbeat: &agent.Heartbeat{
						RoutingInfo: newRoutingInfo(""),
					},
				}, state.RouterChange{}
			},
		},
		"changes, existing agent, event causes changes": {
			before: func() *state.Router {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        newRoutingInfo(""),
						},
					},
				}
			},
			event: func() (*agent.NodeEvent, state.RouterChange) {
				return &agent.NodeEvent{
						NodeID:     uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
						EventIndex: 1,
						Timestamp:  timestamp(1),
						Heartbeat: &agent.Heartbeat{
							RoutingInfo: newRoutingInfo(""),
						},
					}, state.RouterChange{
						UpdatedAgents: map[uuid.UUID]struct{}{
							uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {},
						},
					}
			},
			after: func() *state.Router {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     1,
							LastEventTimestamp: timestamp(1),
							RoutingInfo:        newRoutingInfo(""),
						},
					},
				}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := tc.before()
			ev, wantResult := tc.event()
			gotResult := r.MergeNodeEvent(ev)
			require.Equal(t, wantResult, gotResult)
			if tc.after == nil {
				require.Equal(t, tc.before(), r)
				return
			}

			require.Equal(t, tc.after(), r)
		})
	}
}

func TestRouterMergeHealthcheck(t *testing.T) {
	tests := map[string]struct {
		before func() *state.Router
		event  func() (health.Check, state.RouterChange)
		after  func() *state.Router // if after is nil, we don't expect any changes
	}{
		"changes, first tracked health": {
			before: func() *state.Router {
				return &state.Router{}
			},
			event: func() (health.Check, state.RouterChange) {
				return healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"), state.RouterChange{
					NewHealth: map[uuid.UUID]struct{}{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {},
					},
				}
			},
			after: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
							},
						},
					},
				}
			},
		},
		"changes, additional tracked health": {
			before: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
							},
						},
					},
				}
			},
			event: func() (health.Check, state.RouterChange) {
				return healthCheckWithUUID(1, "01954bd0-f3c3-740e-b149-ad06ad1cebf5"), state.RouterChange{
					NewHealth: map[uuid.UUID]struct{}{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf5"): {},
					},
				}
			},
			after: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
							},
						},
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf5"): {
							History: health.History{
								healthCheckWithUUID(1, "01954bd0-f3c3-740e-b149-ad06ad1cebf5"),
							},
						},
					},
				}
			},
		},
		"no changes, existing tracked health, health check caused no changes": {
			before: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
							},
						},
					},
				}
			},
			event: func() (health.Check, state.RouterChange) {
				return healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"), state.RouterChange{}
			},
		},
		"changes, existing agent, event causes changes": {
			before: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
							},
						},
					},
				}
			},
			event: func() (health.Check, state.RouterChange) {
				return healthCheckWithUUID(1, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"), state.RouterChange{
					UpdatedHealth: map[uuid.UUID]struct{}{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {},
					},
				}
			},
			after: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
								healthCheckWithUUID(1, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
							},
						},
					},
				}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := tc.before()
			ev, wantResult := tc.event()
			gotResult := r.MergeHealthcheck(ev)
			require.Equal(t, wantResult, gotResult)
			if tc.after == nil {
				require.Equal(t, tc.before(), r)
				return
			}
			require.Equal(t, tc.after(), r)
		})
	}
}

func TestRouterMergeState(t *testing.T) {
	tests := map[string]struct {
		before func() *state.Router
		other  func() (*state.Router, state.RouterChange)
		after  func() *state.Router // if after is nil, we don't expect any changes
	}{
		"no changes, same, both empty": {
			before: func() *state.Router {
				return &state.Router{}
			},
			other: func() (*state.Router, state.RouterChange) {
				return &state.Router{}, state.RouterChange{}
			},
		},
		"no changes, both have agents, no merge changes in agents": {
			before: func() *state.Router {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        newRoutingInfo(""),
						},
					},
				}
			},
			other: func() (*state.Router, state.RouterChange) {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        newRoutingInfo(""),
						},
					},
				}, state.RouterChange{}
			},
		},
		"changes, other has agent we're missing": {
			before: func() *state.Router {
				return &state.Router{}
			},
			other: func() (*state.Router, state.RouterChange) {
				return &state.Router{
						Agents: map[uuid.UUID]*state.Agent{
							uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
								LastEventIndex:     0,
								LastEventTimestamp: timestamp(0),
								RoutingInfo:        newRoutingInfo(""),
							},
						},
					}, state.RouterChange{
						NewAgents: map[uuid.UUID]struct{}{
							uuid.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {},
						},
					}
			},
			after: func() *state.Router {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        newRoutingInfo(""),
						},
					},
				}
			},
		},
		"no changes, other has no agents": {
			before: func() *state.Router {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        newRoutingInfo(""),
						},
					},
				}
			},
			other: func() (*state.Router, state.RouterChange) {
				return &state.Router{}, state.RouterChange{}
			},
		},
		"changes, both have agents, merge changes in agents": {
			before: func() *state.Router {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        newRoutingInfo(""),
						},
					},
				}
			},
			other: func() (*state.Router, state.RouterChange) {
				return &state.Router{
						Agents: map[uuid.UUID]*state.Agent{
							uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
								LastEventIndex:     1,
								LastEventTimestamp: timestamp(1),
								RoutingInfo:        newRoutingInfo(""),
							},
						},
					}, state.RouterChange{
						UpdatedAgents: map[uuid.UUID]struct{}{
							uuid.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {},
						},
					}
			},
			after: func() *state.Router {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     1,
							LastEventTimestamp: timestamp(1),
							RoutingInfo:        newRoutingInfo(""),
						},
					},
				}
			},
		},
		"no changes, both have tracked health, no merge changes in tracked health": {
			before: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
							},
						},
					},
				}
			},
			other: func() (*state.Router, state.RouterChange) {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
							},
						},
					},
				}, state.RouterChange{}
			},
		},
		"changes, other has tracked health we're missing": {
			before: func() *state.Router {
				return &state.Router{}
			},
			other: func() (*state.Router, state.RouterChange) {
				return &state.Router{
						Health: map[uuid.UUID]*state.NodeHealth{
							uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
								History: health.History{
									healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
								},
							},
						},
					}, state.RouterChange{
						NewHealth: map[uuid.UUID]struct{}{
							uuid.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {},
						},
					}
			},
			after: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
							},
						},
					},
				}
			},
		},
		"no changes, other has no tracked health": {
			before: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
							},
						},
					},
				}
			},
			other: func() (*state.Router, state.RouterChange) {
				return &state.Router{}, state.RouterChange{}
			},
		},
		"changes, both have tracked health, merge changes in tracked health": {
			before: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
							},
						},
					},
				}
			},
			other: func() (*state.Router, state.RouterChange) {
				return &state.Router{
						Health: map[uuid.UUID]*state.NodeHealth{
							uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
								History: health.History{
									healthCheckWithUUID(1, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
								},
							},
						},
					}, state.RouterChange{
						UpdatedHealth: map[uuid.UUID]struct{}{
							uuid.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {},
						},
					}
			},
			after: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
								healthCheckWithUUID(1, "01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
							},
						},
					},
				}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := tc.before()
			otherState, wantResult := tc.other()
			gotResult := r.MergeState(otherState)
			require.Equal(t, wantResult, gotResult)
			if tc.after == nil {
				require.Equal(t, tc.before(), r)
				return
			}
			wantState := tc.after()
			require.Equal(t, wantState, r)
		})
	}
}

func TestRouterMarshalUnmarshalProto(t *testing.T) {
	const (
		agentID      = "01954bd0-f3c3-740e-b149-ad06ad1cebf6"
		nodeHealthID = "01954bd0-f3c3-740e-b149-ad06ad1cebf5"
	)
	tests := map[string]func(pbr *pb.RouterState, want *state.Router){
		"ok, empty state": func(pbr *pb.RouterState, want *state.Router) {
			pbr.SetAgents(map[string]*pb.AgentState{})
			pbr.SetNodeHealth(map[string]*pb.NodeHealthState{})
			want.Agents = map[uuid.UUID]*state.Agent{}
			want.Health = map[uuid.UUID]*state.NodeHealth{}
		},
		"ok, nil state": func(pbr *pb.RouterState, want *state.Router) {
			pbr.SetAgents(nil)
			pbr.SetNodeHealth(nil)
			want.Agents = nil
			want.Health = nil
		},
		"ok, agents only": func(pbr *pb.RouterState, want *state.Router) {
			pbr.SetNodeHealth(nil)
			want.Health = nil
		},
		"ok, node health only": func(pbr *pb.RouterState, want *state.Router) {
			pbr.SetAgents(nil)
			want.Agents = nil
		},
		"ok, full state": func(pbr *pb.RouterState, want *state.Router) {
			// nothing to change.
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

			his := health.History{
				healthcheck(0),
				healthcheck(1),
				healthcheck(2),
			}
			pbnh := &pb.NodeHealthState{}
			pbnh.SetHistory(his.MarshalProto())

			pbr := &pb.RouterState{}
			pbr.SetAgents(map[string]*pb.AgentState{
				agentID: pba,
			})
			pbr.SetNodeHealth(map[string]*pb.NodeHealthState{
				nodeHealthID: pbnh,
			})

			want := &state.Router{
				Agents: map[uuid.UUID]*state.Agent{
					uuidv7.MustParse(agentID): {
						LastEventIndex:     10,
						LastEventTimestamp: lastEvent,
						RoutingInfo:        newRoutingInfo(""),
						ShutdownAt:         &shutdownAt,
					},
				},
				Health: map[uuid.UUID]*state.NodeHealth{
					uuidv7.MustParse(nodeHealthID): {
						History: his,
					},
				},
			}

			tc(pbr, want)

			got := &state.Router{}
			err := got.UnmarshalProto(pbr)
			require.NoError(t, err)
			require.Equal(t, want, got)

			// check again but with non-hardcoded pb
			pbr = got.MarshalProto()
			err = got.UnmarshalProto(pbr)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}

	failTests := map[string]func(pbr *pb.RouterState){
		"fail, invalid agent id": func(pbr *pb.RouterState) {
			agents := pbr.GetAgents()
			pbr.SetAgents(map[string]*pb.AgentState{
				// v4 uuid
				"e1d4956d-d87e-4bf7-a6f2-b56a983b6f01": agents[agentID],
			})
		},
		"fail, nil agent": func(pbr *pb.RouterState) {
			agents := pbr.GetAgents()
			agents[agentID] = nil
		},
		"fail, invalid agent": func(pbr *pb.RouterState) {
			agents := pbr.GetAgents()
			agents[agentID].SetLastEventIndex(-1) // invalid event index
		},
		"fail, invalid node health id": func(pbr *pb.RouterState) {
			health := pbr.GetNodeHealth()
			pbr.SetNodeHealth(map[string]*pb.NodeHealthState{
				// v4 uuid
				"e1d4956d-d87e-4bf7-a6f2-b56a983b6f01": health[nodeHealthID],
			})
		},
		"fail, nil node health": func(pbr *pb.RouterState) {
			health := pbr.GetNodeHealth()
			health[nodeHealthID] = nil
		},
		"fail, invalid node health": func(pbr *pb.RouterState) {
			health := pbr.GetNodeHealth()
			health[nodeHealthID].ClearHistory() // missing history.
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

			his := health.History{
				healthcheck(0),
				healthcheck(1),
				healthcheck(2),
			}
			pbnh := &pb.NodeHealthState{}
			pbnh.SetHistory(his.MarshalProto())

			pbr := &pb.RouterState{}
			pbr.SetAgents(map[string]*pb.AgentState{
				"01954bd0-f3c3-740e-b149-ad06ad1cebf6": pba,
			})
			pbr.SetNodeHealth(map[string]*pb.NodeHealthState{
				"01954bd0-f3c3-740e-b149-ad06ad1cebf5": pbnh,
			})

			tc(pbr)

			s := &state.Router{}
			err := s.UnmarshalProto(pbr)
			require.Error(t, err)
		})
	}
}

func healthCheckWithUUID(minutes int, id string) health.Check {
	hc := healthcheck(minutes)
	hc.NodeID = uuidv7.MustParse(id)
	return hc
}
