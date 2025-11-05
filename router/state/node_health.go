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

	pb "github.com/openpcc/openpcc/gen/protos/router/cluster"
	"github.com/openpcc/openpcc/router/health"
)

// NodeHealth is the serializable tracked health state a single node from the perspective of the router.
//
// This excludes derived state like the calculated health status of a node.
type NodeHealth struct {
	History health.History
}

// MergeHealthcheck attempts to merge the provided healthcheck into the
// the node health state. If the state changes as a result of this merge, this
// method will return true.
//
// MergeHealthcheck returns false when the health check is for a different node. It
// is up to the caller (usually the [Router]) to ensure that the healthcheck event is
// provided to the right node health state.
func (h *NodeHealth) MergeHealthcheck(hc health.Check) bool {
	newHistory, err := h.History.Insert(hc)
	if err != nil {
		return false
	}

	if len(newHistory) == len(h.History) {
		return false
	}

	h.History = newHistory
	return true
}

// MergeState attempts to merge the other state into this
// state. If the state changes as a result of this merge, this
// method will return true.
//
// After a merge, the other state should no longer be used
// as data referenced in it may now be "owned" by this state.
func (h *NodeHealth) MergeState(other *NodeHealth) bool {
	newHistory, err := h.History.Merge(other.History)
	if err != nil {
		return false
	}

	if len(newHistory) == len(h.History) {
		return false
	}

	h.History = newHistory
	return true
}

func (h *NodeHealth) MarshalProto() *pb.NodeHealthState {
	pbnh := &pb.NodeHealthState{}
	pbnh.SetHistory(h.History.MarshalProto())
	return pbnh
}

func (h *NodeHealth) UnmarshalProto(pbnh *pb.NodeHealthState) error {
	if !pbnh.HasHistory() {
		return errors.New("missing history")
	}

	his := health.History{}
	err := his.UnmarshalProto(pbnh.GetHistory())
	if err != nil {
		return fmt.Errorf("failed to unmarshal history: %w", err)
	}

	h.History = his

	return nil
}
