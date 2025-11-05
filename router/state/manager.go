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

package state

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/openpcc/openpcc/delay"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/router/health"
)

// NodeEvaluator evaluates a node and determines whether it should be part
// of the routing set or not.
//
// The first return value indicates the routing info that should be
// included in the routing set. If this is nil, the routing info should not
// be included in the routing set.
//
// The second return value indicates the duration after which the node should be
// evaluated again. A nil duration indicates the node should be dropped from the
// internal state.
//
// When the second return value is nil, the first return value should also be nil.
type NodeEvaluator interface {
	Evaluate(a *Agent, h *NodeHealth) (*agent.RoutingInfo, *time.Duration)
}

// RoutingSet is called when the routing set is changed in response to evaluations.
type RoutingSet interface {
	Update(adds map[uuid.UUID]*agent.RoutingInfo, deletes ...uuid.UUID)
}

// Manager manages the state of a single router and uses it to derive the set of routable
// nodes. The state is updated in response to received events, external state and time
// moving forward.
//
// The manager uses a [NodeEvaluator] to derive the [RoutingSet] from its state. Each time
// an event or external state results in changes to nodes, those nodes will be re-evaluated.
//
// Events or external state only ever update or add to the internal state of the manager.
//
// Since nodes may be spun down or disappear for any reason, we don't want to keep their data around
// forever. The node evaluator is responsible for indicating that a node can be dropped from the
// internal state.
//
// This process is not modelled as part of the state. Think of it "evicting stale state".
//
// Nodes may disappear without an event ever reaching the manager. The manager needs to periodically
// re-evaluate the existing nodes to determine if they need to be deleted from the routing set, the
// internal state or both.
//
// The first time a node becomes known to the manager, it will have its first background evaluation
// scheduled. After that the async evaluation process will keep scheduling re-evaluations until the
// node evaluator signals the node information can be deleted from the internal state.
//
// Manager needs to be closed using [Manager.Close] to properly clean up the background evaluation routine.
type Manager struct {
	evaluator  NodeEvaluator
	routingSet RoutingSet

	mu    *sync.Mutex
	state *Router

	// knownNodeCount tracks the number of nodes this manager knows about, either as agent state,
	// node health state or both.
	knownNodeCount int

	// bgEvaluations contains the uuid's of evaluations scheduled in the background. Safe for concurrent use.
	bgEvaluations *delay.Pool[uuid.UUID]
}

func NewManager(evaluator NodeEvaluator, routingSet RoutingSet) *Manager {
	m := &Manager{
		evaluator:  evaluator,
		routingSet: routingSet,

		mu:            &sync.Mutex{},
		state:         &Router{},
		bgEvaluations: delay.NewPool[uuid.UUID](0),
	}

	go m.bgEvaluationWorker()

	return m
}

func (r *Manager) bgEvaluationWorker() {
	for {
		delayedNodeID, ok := <-r.bgEvaluations.Output()
		if !ok {
			// when the delay pool is closed, it indicates the worker needs to stop.
			break
		}
		nodeID := delayedNodeID.V

		r.mu.Lock()
		info := r.evaluateNode(nodeID, true) // always schedule the next eval
		if info != nil {
			// add the node to the routing set.
			r.routingSet.Update(map[uuid.UUID]*agent.RoutingInfo{
				nodeID: info,
			})
		} else {
			// delete the node from the routing set.
			r.routingSet.Update(nil, nodeID)
		}
		r.mu.Unlock()
	}
}

func (r *Manager) MergeRouterState(_ context.Context, s *Router) {
	r.mu.Lock()
	defer r.mu.Unlock()

	change := r.state.MergeState(s)
	r.evaluateRouterChange(change)
}

// MergeNodeEvent merges the node event into the internal state and evaluates
// any resulting changes.
func (r *Manager) MergeNodeEvent(_ context.Context, ev *agent.NodeEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	change := r.state.MergeNodeEvent(ev)
	r.evaluateRouterChange(change)
}

// MergeHealthcheck merges the healthcheck into the internal state and evaluates
// any resulting changes.
func (r *Manager) MergeHealthcheck(_ context.Context, hc health.Check) {
	r.mu.Lock()
	defer r.mu.Unlock()
	change := r.state.MergeHealthcheck(hc)
	r.evaluateRouterChange(change)
}

func (r *Manager) evaluateRouterChange(change RouterChange) {
	if !change.ChangedState() {
		// state remained the same, nothing to evaluate.
		return
	}

	var (
		rsAdds = make(map[uuid.UUID]*agent.RoutingInfo, len(change.NewAgents)+len(change.UpdatedAgents))
		rsDels []uuid.UUID
	)

	for nodeID := range change.NodeIDs() {
		isNew := change.IsNewNode(nodeID)
		// need to register the first evaluation if this is a new node.
		info := r.evaluateNode(nodeID, isNew)
		if info != nil {
			rsAdds[nodeID] = info
		} else {
			rsDels = append(rsDels, nodeID)
		}

		if isNew {
			r.knownNodeCount++
		}
	}

	r.routingSet.Update(rsAdds, rsDels...)
}

func (r *Manager) evaluateNode(nodeID uuid.UUID, scheduleBgEval bool) *agent.RoutingInfo {
	// okay if a or health are nil, the evaluator
	// should be able to handle that per the contract.
	a := r.state.Agents[nodeID]
	nh := r.state.Health[nodeID]
	info, nextCheck := r.evaluator.Evaluate(a, nh)
	if nextCheck != nil {
		if scheduleBgEval {
			err := r.bgEvaluations.Add(context.Background(), nodeID, *nextCheck)
			if err != nil {
				slog.Error("failed to schedule next background evaluation for node", "node_id", nodeID)
			}
		}
	} else {
		// no next check scheduled evict the node from the state.
		delete(r.state.Agents, nodeID)
		delete(r.state.Health, nodeID)
		r.knownNodeCount--
	}

	return info
}

// KnownNodeCount returns the number of nodes this manager knows about.
func (r *Manager) KnownNodeCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.knownNodeCount
}

func (r *Manager) ReadState(readFunc func(r *Router)) {
	r.mu.Lock()
	readFunc(r.state)
	r.mu.Unlock()
}

func (r *Manager) Close() {
	r.bgEvaluations.CloseImmediate()
}
