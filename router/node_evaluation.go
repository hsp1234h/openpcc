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
	"log/slog"
	"time"

	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/router/health"
	"github.com/openpcc/openpcc/router/state"
)

type NodeEvaluationFunc func(a *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration)

func (f NodeEvaluationFunc) Evaluate(a *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
	return f(a, nh)
}

func GradedNodeEvaluator(g *health.Grader, interval time.Duration) NodeEvaluationFunc {
	return func(a *state.Agent, nh *state.NodeHealth) (*agent.RoutingInfo, *time.Duration) {
		if a == nil && nh == nil {
			// evict nodes for which we have no state.
			return nil, nil
		}

		// check if anything we received from the agent invalidates this node.
		if a != nil {
			// drop nodes that have shutdown from the state.
			if a.ShutdownAt != nil {
				slog.Info("agent has shutdown, removing from router", "agent", a)
				return nil, nil
			}

			// drop nodes for which we haven't received a heartbeat in a while.
			cutoff := time.Now().Add(-g.MaxAge())
			if a.LastEventTimestamp.Before(cutoff) {
				return nil, nil
			}
		}

		// if we made it here, nothing in the agent suggest we need to evict it.
		// we now grade the health history, or an empty history if this node has no
		// health information yet.

		var history health.History
		if nh != nil {
			history = nh.History
		}

		status := g.Grade(history)
		switch status {
		case health.StatusOK:
			// healthy, route to the node if we have the routing info and schedule the next evaluation.
			return a.RoutingInfo, &interval
		case health.StatusUnknown:
			// don't route to nodes with an unknown status, but don't drop them (yet). Schedule a next evaluation.
			return nil, &interval
		case health.StatusUnavailable:
			// drop unavailable nodes.
			fallthrough
		default:
			// should not happen, but drop nodes with unexpected status.
			return nil, nil
		}
	}
}
