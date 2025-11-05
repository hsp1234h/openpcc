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
	"fmt"

	"github.com/google/uuid"
	pb "github.com/openpcc/openpcc/gen/protos/router/cluster"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/router/health"
	"github.com/openpcc/openpcc/uuidv7"
	"google.golang.org/protobuf/proto"
)

// Router contains the serializable state of a single router.
//
// This excludes derived state like the calculated health status of a node.
type Router struct {
	Agents map[uuid.UUID]*Agent
	Health map[uuid.UUID]*NodeHealth
}

// MergeNodeEvent attempts to merge the provided node event into the
// the router state. If the state changes as a result of this merge, this
// method will return true.
func (r *Router) MergeNodeEvent(e *agent.NodeEvent) RouterChange {
	if r.Agents == nil {
		r.Agents = map[uuid.UUID]*Agent{}
	}

	result := RouterChange{}

	a, ok := r.Agents[e.NodeID]
	if !ok {
		a = &Agent{}
		r.Agents[e.NodeID] = a
		result.NewAgents = map[uuid.UUID]struct{}{
			e.NodeID: {},
		}
	}

	updated := a.MergeNodeEvent(e)
	if updated && len(result.NewAgents) == 0 {
		result.UpdatedAgents = map[uuid.UUID]struct{}{
			e.NodeID: {},
		}
	}

	return result
}

// MergeHealthcheck attempts to merge the provided healthcheck into the
// the router state. If the state changes as a result of this merge, this
// method will return true.
func (r *Router) MergeHealthcheck(hc health.Check) RouterChange {
	if r.Health == nil {
		r.Health = map[uuid.UUID]*NodeHealth{}
	}

	result := RouterChange{}

	nh, ok := r.Health[hc.NodeID]
	if !ok {
		nh = &NodeHealth{}
		r.Health[hc.NodeID] = nh
		result.NewHealth = map[uuid.UUID]struct{}{
			hc.NodeID: {},
		}
	}

	updated := nh.MergeHealthcheck(hc)
	if updated && len(result.NewHealth) == 0 {
		result.UpdatedHealth = map[uuid.UUID]struct{}{
			hc.NodeID: {},
		}
	}

	return result
}

// MergeState attempts to merge the other state into this
// state. If the state changes as a result of this merge, this
// method will return the added nodes (first return value), and the updated
// nodes (second return value).
//
// After a merge, the other state should no longer be used
// as data referenced in it may now be "owned" by this state.
func (r *Router) MergeState(other *Router) RouterChange {
	var result RouterChange
	for key, otherAgent := range other.Agents {
		a, ok := r.Agents[key]
		if ok {
			// merge the other agent with our agent and see if it resulted in changes.
			if a.MergeState(otherAgent) {
				// updated agent
				result.UpdatedAgents = resultNodeID(result.UpdatedAgents, key)
			}
			continue
		}

		// we didn't know about this agent yet.
		if r.Agents == nil {
			r.Agents = map[uuid.UUID]*Agent{}
		}

		r.Agents[key] = otherAgent

		// new agent
		result.NewAgents = resultNodeID(result.NewAgents, key)
	}

	for key, otherNH := range other.Health {
		nh, ok := r.Health[key]
		if ok {
			// merge the other tracked health with our tracked health and
			// see if it resulted in changes.
			if nh.MergeState(otherNH) {
				// updated health
				result.UpdatedHealth = resultNodeID(result.UpdatedHealth, key)
			}
			continue
		}

		// we didn't know about this tracked health yet.
		if r.Health == nil {
			r.Health = map[uuid.UUID]*NodeHealth{}
		}

		r.Health[key] = otherNH

		// new health
		result.NewHealth = resultNodeID(result.NewHealth, key)
	}

	return result
}

func (r *Router) UnmarshalBinary(b []byte) error {
	pbr := &pb.RouterState{}
	err := proto.Unmarshal(b, pbr)
	if err != nil {
		return err
	}

	return r.UnmarshalProto(pbr)
}

func (r *Router) MarshalBinary() ([]byte, error) {
	return proto.Marshal(r.MarshalProto())
}

func (r *Router) MarshalProto() *pb.RouterState {
	pbr := &pb.RouterState{}

	if r.Agents == nil {
		pbr.SetAgents(nil)
	} else {
		pbagents := make(map[string]*pb.AgentState, len(r.Agents))
		for key, r := range r.Agents {
			pbagents[key.String()] = r.MarshalProto()
		}
		pbr.SetAgents(pbagents)
	}

	if r.Health == nil {
		pbr.SetNodeHealth(nil)
	} else {
		pbhealth := make(map[string]*pb.NodeHealthState, len(r.Health))
		for key, h := range r.Health {
			pbhealth[key.String()] = h.MarshalProto()
		}
		pbr.SetNodeHealth(pbhealth)
	}

	return pbr
}

func (r *Router) UnmarshalProto(pbr *pb.RouterState) error {
	var (
		agents     map[uuid.UUID]*Agent
		nodeHealth map[uuid.UUID]*NodeHealth
	)

	pbAgents := pbr.GetAgents()
	if pbAgents != nil {
		agents = make(map[uuid.UUID]*Agent, len(pbAgents))
		for key, pba := range pbAgents {
			id, err := uuidv7.Parse(key)
			if err != nil {
				return fmt.Errorf("failed to parse uuid v7 for agent: %w", err)
			}
			if pba == nil {
				return fmt.Errorf("%s: nil agent", id)
			}

			a := &Agent{}
			err = a.UnmarshalProto(pba)
			if err != nil {
				return fmt.Errorf("%s: failed to unmarshal agent protobuf: %w", id, err)
			}

			agents[id] = a
		}
	}

	pbHealth := pbr.GetNodeHealth()
	if pbHealth != nil {
		nodeHealth = make(map[uuid.UUID]*NodeHealth, len(pbHealth))
		for key, pbh := range pbHealth {
			id, err := uuidv7.Parse(key)
			if err != nil {
				return fmt.Errorf("failed to parse uuid v7 for node health: %w", err)
			}
			if pbh == nil {
				return fmt.Errorf("%s: nil node health", id)
			}

			nh := &NodeHealth{}
			err = nh.UnmarshalProto(pbh)
			if err != nil {
				return fmt.Errorf("%s: failed to unmarshal node health protobuf: %w", id, err)
			}

			nodeHealth[id] = nh
		}
	}

	r.Agents = agents
	r.Health = nodeHealth

	return nil
}

func resultNodeID(m map[uuid.UUID]struct{}, key uuid.UUID) map[uuid.UUID]struct{} {
	if m == nil {
		m = make(map[uuid.UUID]struct{}, 1)
	}
	m[key] = struct{}{}
	return m
}

// RouterChange contains the summary of changes made to a router state.
type RouterChange struct {
	NewAgents     map[uuid.UUID]struct{}
	UpdatedAgents map[uuid.UUID]struct{}
	NewHealth     map[uuid.UUID]struct{}
	UpdatedHealth map[uuid.UUID]struct{}
}

func (r RouterChange) ChangedState() bool {
	return r.Changes() > 0
}

func (r RouterChange) Changes() int {
	return len(r.NewAgents) + len(r.UpdatedAgents) + len(r.NewHealth) + len(r.UpdatedHealth)
}

func (r RouterChange) IsNewNode(id uuid.UUID) bool {
	if len(r.NewAgents) > 0 {
		_, ok := r.NewAgents[id]
		return ok
	}

	if len(r.NewHealth) > 0 {
		_, ok := r.NewHealth[id]
		return ok
	}

	return false
}

func (r RouterChange) NodeIDs() map[uuid.UUID]struct{} {
	if r.Changes() == 0 {
		return nil
	}

	out := make(map[uuid.UUID]struct{}, r.Changes())
	mergeNodeIDs(r.NewAgents, out)
	mergeNodeIDs(r.UpdatedAgents, out)
	mergeNodeIDs(r.NewHealth, out)
	mergeNodeIDs(r.UpdatedHealth, out)
	return out
}

func mergeNodeIDs(src, dst map[uuid.UUID]struct{}) {
	for srcID := range src {
		dst[srcID] = struct{}{}
	}
}
