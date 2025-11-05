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
	"maps"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/router/health"
	"github.com/openpcc/openpcc/router/state"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type routingSetTest struct {
	initialState   func() (*state.Router, map[uuid.UUID]*agent.RoutingInfo)
	state          func() *state.Router
	nodeEvent      func() *agent.NodeEvent
	healthcheck    func() health.Check
	evalFunc       func(t *testing.T, agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration)
	wantRoutingSet func() map[uuid.UUID]*agent.RoutingInfo
	wantKnownNodes int
}

func (tc *routingSetTest) run(t *testing.T) {
	evaluator := &fakeNodeEvaluator{}
	if tc.evalFunc != nil {
		evaluator.evalFunc = func(agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
			return tc.evalFunc(t, agent, nh)
		}
	}
	rs := newRoutingSet()

	m := state.NewManager(evaluator, rs)
	defer m.Close()

	if tc.initialState != nil {
		state, wantRS := tc.initialState()
		m.MergeRouterState(t.Context(), state)
		require.Equal(t, wantRS, rs.Items())
	}

	if tc.state != nil {
		m.MergeRouterState(t.Context(), tc.state())
	}
	if tc.nodeEvent != nil {
		m.MergeNodeEvent(t.Context(), tc.nodeEvent())
	}
	if tc.healthcheck != nil {
		m.MergeHealthcheck(t.Context(), tc.healthcheck())
	}

	require.Equal(t, tc.wantRoutingSet(), rs.Items())
	require.Equal(t, tc.wantKnownNodes, m.KnownNodeCount())
}

func TestManagerMergeRouterState(t *testing.T) {
	tests := map[string]routingSetTest{
		"merge does not change state, nothing to evaluate": {
			state: func() *state.Router {
				return &state.Router{}
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return make(map[uuid.UUID]*agent.RoutingInfo)
			},
			wantKnownNodes: 0,
		},
		"state adds new agent, evaluated to routing set": {
			state: func() *state.Router {
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
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{
					uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): newRoutingInfo(""),
				}
			},
			wantKnownNodes: 1,
		},
		"state adds new agent, not evaluated to routing set": {
			state: func() *state.Router {
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
			evalFunc: func(t *testing.T, agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
				nextCheck := time.Minute
				return nil, &nextCheck
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{}
			},
			wantKnownNodes: 1,
		},
		"state adds multiple new agents, evaluated to routing set": {
			state: func() *state.Router {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        newRoutingInfo("0"),
						},
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3e"): {
							LastEventIndex:     1,
							LastEventTimestamp: timestamp(1),
							RoutingInfo:        newRoutingInfo("1"),
						},
					},
				}
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{
					uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): newRoutingInfo("0"),
					uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3e"): newRoutingInfo("1"),
				}
			},
			wantKnownNodes: 2,
		},
		"state updates existing agent, evaluated to routing set": {
			initialState: func() (*state.Router, map[uuid.UUID]*agent.RoutingInfo) {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        nil,
						},
					},
				}, map[uuid.UUID]*agent.RoutingInfo{}
			},
			state: func() *state.Router {
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
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{
					uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): newRoutingInfo(""),
				}
			},
			wantKnownNodes: 1,
		},
		"state updates existing agent, evaluated to eviction": {
			initialState: func() (*state.Router, map[uuid.UUID]*agent.RoutingInfo) {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        nil,
						},
					},
				}, map[uuid.UUID]*agent.RoutingInfo{}
			},
			state: func() *state.Router {
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
			evalFunc: func(t *testing.T, agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
				// evict from internal state
				return nil, nil
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{}
			},
			wantKnownNodes: 0,
		},
		"state adds new node health, evaluated to routing set": {
			state: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							History: health.History{},
						},
					},
				}
			},
			evalFunc: func(t *testing.T, agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
				// not really something that should happen in reality as the evaluation function should
				// take the routing info from the agent, but just to test the logic.
				nextCheck := time.Minute
				return newRoutingInfo(""), &nextCheck
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{
					uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): newRoutingInfo(""),
				}
			},
			wantKnownNodes: 1,
		},
		"state adds new node health, not evaluated to routing set": {
			state: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							History: health.History{},
						},
					},
				}
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{}
			},
			wantKnownNodes: 1,
		},
		"state updates existing node health, evaluated to routing set": {
			initialState: func() (*state.Router, map[uuid.UUID]*agent.RoutingInfo) {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-da22-7aed-858a-7da965fcee3f"),
							},
						},
					},
				}, map[uuid.UUID]*agent.RoutingInfo{}
			},
			state: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							History: health.History{
								healthCheckWithUUID(1, "01954bd0-da22-7aed-858a-7da965fcee3f"),
							},
						},
					},
				}
			},
			evalFunc: func(t *testing.T, agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
				// not really something that should happen in reality as the evaluation function should
				// take the routing info from the agent, but just to test the logic.
				nextCheck := time.Minute
				if len(nh.History) == 1 {
					return nil, &nextCheck
				}
				return newRoutingInfo(""), &nextCheck
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{
					uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): newRoutingInfo(""),
				}
			},
			wantKnownNodes: 1,
		},
		"state updates existing node health, not evaluated to routing set": {
			initialState: func() (*state.Router, map[uuid.UUID]*agent.RoutingInfo) {
				return &state.Router{
						Health: map[uuid.UUID]*state.NodeHealth{
							uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
								History: health.History{
									healthCheckWithUUID(0, "01954bd0-da22-7aed-858a-7da965fcee3f"),
								},
							},
						},
					}, map[uuid.UUID]*agent.RoutingInfo{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): newRoutingInfo(""),
					}
			},
			state: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							History: health.History{
								healthCheckWithUUID(1, "01954bd0-da22-7aed-858a-7da965fcee3f"),
							},
						},
					},
				}
			},
			evalFunc: func(t *testing.T, agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
				// not really something that should happen in reality as the evaluation function should
				// take the routing info from the agent, but just to test the logic.
				nextCheck := time.Minute
				if len(nh.History) == 1 {
					return newRoutingInfo(""), &nextCheck
				}
				return nil, &nextCheck
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{}
			},
			wantKnownNodes: 1,
		},
		"state updates existing node health, evaluated to eviction": {
			initialState: func() (*state.Router, map[uuid.UUID]*agent.RoutingInfo) {
				return &state.Router{
						Health: map[uuid.UUID]*state.NodeHealth{
							uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
								History: health.History{
									healthCheckWithUUID(0, "01954bd0-da22-7aed-858a-7da965fcee3f"),
								},
							},
						},
					}, map[uuid.UUID]*agent.RoutingInfo{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): newRoutingInfo(""),
					}
			},
			state: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							History: health.History{
								healthCheckWithUUID(1, "01954bd0-da22-7aed-858a-7da965fcee3f"),
							},
						},
					},
				}
			},
			evalFunc: func(t *testing.T, agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
				// not really something that should happen in reality as the evaluation function should
				// take the routing info from the agent, but just to test the logic.
				if nh != nil && len(nh.History) == 1 {
					nextCheck := time.Minute
					return newRoutingInfo(""), &nextCheck
				}
				// evict from internal state
				return nil, nil
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{}
			},
			wantKnownNodes: 0,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc.run(t)
		})
	}
}

func TestManagerMergeNodeEvent(t *testing.T) {
	tests := map[string]routingSetTest{
		"event does not change state, nothing to evaluate": {
			initialState: func() (*state.Router, map[uuid.UUID]*agent.RoutingInfo) {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        nil,
						},
					},
				}, map[uuid.UUID]*agent.RoutingInfo{}
			},
			nodeEvent: func() *agent.NodeEvent {
				// already handled this heartbeat event.
				return &agent.NodeEvent{
					EventIndex: 0,
					NodeID:     uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
					Timestamp:  timestamp(0),
					Heartbeat: &agent.Heartbeat{
						RoutingInfoURL: test.Must(url.Parse("http://127.0.0.1")),
					},
				}
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{}
			},
			wantKnownNodes: 1,
		},
		"event adds new agent, evaluated to routing set": {
			nodeEvent: func() *agent.NodeEvent {
				return &agent.NodeEvent{
					EventIndex: 0,
					NodeID:     uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
					Timestamp:  timestamp(0),
					Heartbeat: &agent.Heartbeat{
						RoutingInfo: newRoutingInfo(""),
					},
				}
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{
					uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): newRoutingInfo(""),
				}
			},
			wantKnownNodes: 1,
		},
		"event adds new agent, not evaluated to routing set": {
			nodeEvent: func() *agent.NodeEvent {
				return &agent.NodeEvent{
					EventIndex: 0,
					NodeID:     uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
					Timestamp:  timestamp(0),
					Heartbeat: &agent.Heartbeat{
						RoutingInfo: newRoutingInfo(""),
					},
				}
			},
			evalFunc: func(t *testing.T, agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
				nextCheck := time.Minute
				return nil, &nextCheck
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{}
			},
			wantKnownNodes: 1,
		},
		"event updates agent, evaluated to routing set": {
			initialState: func() (*state.Router, map[uuid.UUID]*agent.RoutingInfo) {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        nil,
						},
					},
				}, map[uuid.UUID]*agent.RoutingInfo{}
			},
			nodeEvent: func() *agent.NodeEvent {
				return &agent.NodeEvent{
					EventIndex: 1,
					NodeID:     uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
					Timestamp:  timestamp(1),
					Heartbeat: &agent.Heartbeat{
						RoutingInfo: newRoutingInfo(""),
					},
				}
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{
					uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): newRoutingInfo(""),
				}
			},
			wantKnownNodes: 1,
		},
		"event updates agent, not evaluated to routing set": {
			initialState: func() (*state.Router, map[uuid.UUID]*agent.RoutingInfo) {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        nil,
						},
					},
				}, map[uuid.UUID]*agent.RoutingInfo{}
			},
			nodeEvent: func() *agent.NodeEvent {
				return &agent.NodeEvent{
					EventIndex: 1,
					NodeID:     uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
					Timestamp:  timestamp(1),
					Heartbeat: &agent.Heartbeat{
						RoutingInfo: newRoutingInfo(""),
					},
				}
			},
			evalFunc: func(t *testing.T, agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
				nextCheck := time.Minute
				return nil, &nextCheck
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{}
			},
			wantKnownNodes: 1,
		},
		"event updates agent, evaluated to eviction": {
			initialState: func() (*state.Router, map[uuid.UUID]*agent.RoutingInfo) {
				return &state.Router{
					Agents: map[uuid.UUID]*state.Agent{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							LastEventIndex:     0,
							LastEventTimestamp: timestamp(0),
							RoutingInfo:        nil,
						},
					},
				}, map[uuid.UUID]*agent.RoutingInfo{}
			},
			nodeEvent: func() *agent.NodeEvent {
				return &agent.NodeEvent{
					EventIndex: 1,
					NodeID:     uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
					Timestamp:  timestamp(1),
					Heartbeat: &agent.Heartbeat{
						RoutingInfo: newRoutingInfo(""),
					},
				}
			},
			evalFunc: func(t *testing.T, agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
				// evict from internal state
				return nil, nil
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{}
			},
			wantKnownNodes: 0,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc.run(t)
		})
	}
}

func TestManagerMergeHealthcheck(t *testing.T) {
	tests := map[string]routingSetTest{
		"healthcheck does not change state, nothing to evaluate": {
			initialState: func() (*state.Router, map[uuid.UUID]*agent.RoutingInfo) {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-da22-7aed-858a-7da965fcee3f"),
							},
						},
					},
				}, map[uuid.UUID]*agent.RoutingInfo{}
			},
			healthcheck: func() health.Check {
				return healthCheckWithUUID(0, "01954bd0-da22-7aed-858a-7da965fcee3f")
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{}
			},
			wantKnownNodes: 1,
		},
		"healthcheck adds new node health, evaluated to routing set": {
			healthcheck: func() health.Check {
				return healthCheckWithUUID(0, "01954bd0-da22-7aed-858a-7da965fcee3f")
			},
			evalFunc: func(t *testing.T, agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
				// not really something that should happen in reality as the evaluation function should
				// take the routing info from the agent, but just to test the logic.
				nextCheck := time.Minute
				return newRoutingInfo(""), &nextCheck
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{
					uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): newRoutingInfo(""),
				}
			},
			wantKnownNodes: 1,
		},
		"healthcheck adds new node health, not evaluated to routing set": {
			healthcheck: func() health.Check {
				return healthCheckWithUUID(0, "01954bd0-da22-7aed-858a-7da965fcee3f")
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{}
			},
			wantKnownNodes: 1,
		},
		"healthcheck updates existing node health, evaluated to routing set": {
			initialState: func() (*state.Router, map[uuid.UUID]*agent.RoutingInfo) {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							History: health.History{
								healthCheckWithUUID(0, "01954bd0-da22-7aed-858a-7da965fcee3f"),
							},
						},
					},
				}, map[uuid.UUID]*agent.RoutingInfo{}
			},
			healthcheck: func() health.Check {
				return healthCheckWithUUID(1, "01954bd0-da22-7aed-858a-7da965fcee3f")
			},
			evalFunc: func(t *testing.T, agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
				// not really something that should happen in reality as the evaluation function should
				// take the routing info from the agent, but just to test the logic.
				nextCheck := time.Minute
				if len(nh.History) == 1 {
					return nil, &nextCheck
				}
				return newRoutingInfo(""), &nextCheck
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{
					uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): newRoutingInfo(""),
				}
			},
			wantKnownNodes: 1,
		},
		"healthcheck updates existing node health, not evaluated to routing set": {
			initialState: func() (*state.Router, map[uuid.UUID]*agent.RoutingInfo) {
				return &state.Router{
						Health: map[uuid.UUID]*state.NodeHealth{
							uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
								History: health.History{
									healthCheckWithUUID(0, "01954bd0-da22-7aed-858a-7da965fcee3f"),
								},
							},
						},
					}, map[uuid.UUID]*agent.RoutingInfo{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): newRoutingInfo(""),
					}
			},
			healthcheck: func() health.Check {
				return healthCheckWithUUID(1, "01954bd0-da22-7aed-858a-7da965fcee3f")
			},
			evalFunc: func(t *testing.T, agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
				// not really something that should happen in reality as the evaluation function should
				// take the routing info from the agent, but just to test the logic.
				nextCheck := time.Minute
				if len(nh.History) == 1 {
					return newRoutingInfo(""), &nextCheck
				}
				return nil, &nextCheck
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{}
			},
			wantKnownNodes: 1,
		},
		"healthcheck updates existing node health, evaluates to eviction": {
			initialState: func() (*state.Router, map[uuid.UUID]*agent.RoutingInfo) {
				return &state.Router{
						Health: map[uuid.UUID]*state.NodeHealth{
							uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
								History: health.History{
									healthCheckWithUUID(0, "01954bd0-da22-7aed-858a-7da965fcee3f"),
								},
							},
						},
					}, map[uuid.UUID]*agent.RoutingInfo{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): newRoutingInfo(""),
					}
			},
			healthcheck: func() health.Check {
				return healthCheckWithUUID(1, "01954bd0-da22-7aed-858a-7da965fcee3f")
			},
			evalFunc: func(t *testing.T, agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
				// not really something that should happen in reality as the evaluation function should
				// take the routing info from the agent, but just to test the logic.
				nextCheck := time.Minute
				if nh != nil && len(nh.History) == 1 {
					return newRoutingInfo(""), &nextCheck
				}
				// evict from internal state
				return nil, nil
			},
			wantRoutingSet: func() map[uuid.UUID]*agent.RoutingInfo {
				return map[uuid.UUID]*agent.RoutingInfo{}
			},
			wantKnownNodes: 0,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc.run(t)
		})
	}
}

func TestManagerBackgroundEvaluations(t *testing.T) {
	tests := map[string]struct {
		state       func() *state.Router
		nodeEvent   func() *agent.NodeEvent
		healthcheck func() health.Check
	}{
		"triggered by state, new agent": {
			state: func() *state.Router {
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
		"triggered by state, new node health": {
			state: func() *state.Router {
				return &state.Router{
					Health: map[uuid.UUID]*state.NodeHealth{
						uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"): {
							History: health.History{},
						},
					},
				}
			},
		},
		"triggered by node event": {
			nodeEvent: func() *agent.NodeEvent {
				return &agent.NodeEvent{
					EventIndex: 1,
					NodeID:     uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
					Timestamp:  timestamp(1),
					Heartbeat: &agent.Heartbeat{
						RoutingInfo: newRoutingInfo(""),
					},
				}
			},
		},
		"trigger by healthcheck": {
			healthcheck: func() health.Check {
				return healthcheck(0)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name+", not evicted", func(t *testing.T) {
			t.Parallel()

			evaluator := newFailingNodeEvaluator(5, 5*time.Millisecond, false)
			rs := newRoutingSet()
			m := state.NewManager(evaluator, rs)
			defer m.Close()

			if tc.state != nil {
				m.MergeRouterState(t.Context(), tc.state())
			}

			if tc.nodeEvent != nil {
				m.MergeNodeEvent(t.Context(), tc.nodeEvent())
			}

			if tc.healthcheck != nil {
				m.MergeHealthcheck(t.Context(), tc.healthcheck())
			}

			require.Equal(t, 1, len(rs.Items()))
			require.Equal(t, 1, m.KnownNodeCount())

			// wait for the evaluations to fail and the node to be removed from the routing set.
			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				require.Equal(collect, 0, len(rs.Items()))
			}, 1*time.Second, 5*time.Millisecond)

			require.Equal(t, 1, m.KnownNodeCount()) // not evicted, so manager still knows about this node.
		})

		t.Run(name+", evicted", func(t *testing.T) {
			t.Parallel()
			evaluator := newFailingNodeEvaluator(5, 5*time.Millisecond, true)
			rs := newRoutingSet()
			m := state.NewManager(evaluator, rs)
			defer m.Close()

			if tc.state != nil {
				m.MergeRouterState(t.Context(), tc.state())
			}

			if tc.nodeEvent != nil {
				m.MergeNodeEvent(t.Context(), tc.nodeEvent())
			}

			if tc.healthcheck != nil {
				m.MergeHealthcheck(t.Context(), tc.healthcheck())
			}

			require.Equal(t, 1, len(rs.Items()))
			require.Equal(t, 1, m.KnownNodeCount())

			// wait for the evaluations to fail and the node to be removed from the routing set.
			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				require.Equal(collect, 0, len(rs.Items()))
			}, 1*time.Second, 5*time.Millisecond)

			require.Equal(t, 0, m.KnownNodeCount()) // evicted, so manager should no longer know about this node.
		})
	}
}

type fakeNodeEvaluator struct {
	evalFunc func(agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration)
}

func (e *fakeNodeEvaluator) Evaluate(agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
	if e.evalFunc != nil {
		return e.evalFunc(agent, nh)
	}
	nextCheck := time.Minute
	if agent != nil {
		return agent.RoutingInfo, &nextCheck
	}
	return nil, &nextCheck
}

type failingNodeEvaluator struct {
	mu       *sync.Mutex
	calls    int
	max      int
	duration time.Duration
	evict    bool
}

func newFailingNodeEvaluator(maxCalls int, duration time.Duration, evict bool) *failingNodeEvaluator {
	return &failingNodeEvaluator{
		mu:       &sync.Mutex{},
		calls:    0,
		max:      maxCalls,
		duration: duration,
		evict:    evict,
	}
}

func (e *failingNodeEvaluator) Evaluate(agent *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
	e.mu.Lock()
	defer func() {
		e.calls++
		e.mu.Unlock()
	}()

	if e.calls > e.max {
		if e.evict {
			return nil, nil
		}
		return nil, &e.duration
	}
	// normally should return the agent routing info, but we don't care about that for these tests.
	return newRoutingInfo(""), &e.duration
}

type routingSet struct {
	mu    *sync.Mutex
	items map[uuid.UUID]*agent.RoutingInfo
}

func newRoutingSet() *routingSet {
	return &routingSet{
		mu:    &sync.Mutex{},
		items: map[uuid.UUID]*agent.RoutingInfo{},
	}
}

func (s *routingSet) Update(items map[uuid.UUID]*agent.RoutingInfo, ids ...uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, val := range items {
		s.items[key] = val
	}
	for _, id := range ids {
		delete(s.items, id)
	}
}

func (s *routingSet) Items() map[uuid.UUID]*agent.RoutingInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	return maps.Clone(s.items)
}
