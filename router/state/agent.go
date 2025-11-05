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
	"errors"
	"fmt"
	"time"

	pb "github.com/openpcc/openpcc/gen/protos/router/cluster"
	"github.com/openpcc/openpcc/router/agent"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Agent contains the serializable state of an agent from the perspective of the router.
//
// An agent runs on a node and is responsible for sending node events to the router.
type Agent struct {
	LastEventIndex     int64
	LastEventTimestamp time.Time
	// RoutingInfo is assumed to be immutable. It can be missing from heartbeat events, but once it's
	// set it will not change.
	RoutingInfo *agent.RoutingInfo
	ShutdownAt  *time.Time
}

func (a *Agent) isNewAgent() bool {
	return a.LastEventTimestamp.IsZero()
}

func (a *Agent) CanHealthcheck() bool {
	return a.RoutingInfo != nil && a.ShutdownAt == nil
}

// MergeNodeEvent attempts to merge the provided node event into the
// the agent state. If the state changes as a result of this merge, this
// method will return true.
//
// MergeNodeEvent does not checks NodeID's. It is up to the caller (usually the [Router])
// to ensure that the right event is provided to the right agent.
func (a *Agent) MergeNodeEvent(e *agent.NodeEvent) bool {
	if a.isNewAgent() || e.EventIndex > a.LastEventIndex {
		a.LastEventIndex = e.EventIndex
		a.LastEventTimestamp = e.Timestamp

		if a.RoutingInfo == nil && e.Heartbeat != nil && e.Heartbeat.RoutingInfo != nil {
			a.RoutingInfo = e.Heartbeat.RoutingInfo
		}

		if e.IsShutdownEvent() {
			ts := e.Timestamp
			a.ShutdownAt = &ts
		}

		return true
	}

	if a.RoutingInfo == nil && e.Heartbeat != nil && e.Heartbeat.RoutingInfo != nil {
		a.RoutingInfo = e.Heartbeat.RoutingInfo
		return true
	}

	return false
}

// MergeState attempts to merge the other state into this
// state. If the state changes as a result of this merge, this
// method will return true.
//
// After a merge, the other state should no longer be used
// as data referenced in it may now be "owned" by this state.
func (a *Agent) MergeState(other *Agent) bool {
	changes := 0
	if a.LastEventIndex < other.LastEventIndex {
		a.LastEventIndex = other.LastEventIndex
		a.LastEventTimestamp = other.LastEventTimestamp
		if other.ShutdownAt != nil {
			a.ShutdownAt = other.ShutdownAt
		}
		changes++
	}

	if a.RoutingInfo == nil && other.RoutingInfo != nil {
		a.RoutingInfo = other.RoutingInfo
		changes++
	}

	return changes > 0
}

func (a *Agent) MarshalProto() *pb.AgentState {
	pba := &pb.AgentState{}
	pba.SetLastEventIndex(a.LastEventIndex)
	pba.SetLastEventTimestamp(timestamppb.New(a.LastEventTimestamp))
	if a.RoutingInfo != nil {
		pba.SetRoutingInfo(a.RoutingInfo.MarshalProto())
	}
	if a.ShutdownAt != nil {
		pba.SetShutdownAt(timestamppb.New(*a.ShutdownAt))
	}
	return pba
}

func (a *Agent) UnmarshalProto(pba *pb.AgentState) error {
	if !pba.HasLastEventIndex() || !pba.HasLastEventTimestamp() {
		return errors.New("no event data")
	}

	lastEvIndex := pba.GetLastEventIndex()
	lastEvTimestamp := pba.GetLastEventTimestamp().AsTime()

	if lastEvIndex < 0 {
		return fmt.Errorf("last event index must be 0 or greater, got %d", lastEvIndex)
	}

	var rInfo *agent.RoutingInfo
	if pba.HasRoutingInfo() {
		rInfo = &agent.RoutingInfo{}
		err := rInfo.UnmarshalProto(pba.GetRoutingInfo())
		if err != nil {
			return fmt.Errorf("failed to unmarshal routing info: %w", err)
		}
	}

	var shutdownAt *time.Time
	if pba.HasShutdownAt() {
		t := pba.GetShutdownAt().AsTime()
		shutdownAt = &t
	}

	a.LastEventIndex = lastEvIndex
	a.LastEventTimestamp = lastEvTimestamp
	a.RoutingInfo = rInfo
	a.ShutdownAt = shutdownAt

	return nil
}
