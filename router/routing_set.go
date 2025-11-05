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
	"maps"
	"sync"

	"github.com/google/uuid"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/router/api"
)

// routingSet is the set of nodes that the state manager has made available.
type routingSet struct {
	mu    *sync.RWMutex
	nodes map[uuid.UUID]*agent.RoutingInfo
}

func newRoutingSet() *routingSet {
	return &routingSet{
		mu:    &sync.RWMutex{},
		nodes: map[uuid.UUID]*agent.RoutingInfo{},
	}
}

func (r *routingSet) Update(add map[uuid.UUID]*agent.RoutingInfo, deletes ...uuid.UUID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, info := range add {
		r.nodes[id] = info
	}
	for _, id := range deletes {
		delete(r.nodes, id)
	}
}

func (r *routingSet) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.nodes)
}

func (r *routingSet) queryComputeManifests(q *api.ComputeManifestRequest) api.ComputeManifestList {
	if q.Limit <= 0 {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	var list api.ComputeManifestList
	for id, node := range r.nodes {
		if len(list) == q.Limit {
			return list
		}

		if node.Tags.ContainsAll(q.Tags) {
			list = append(list, api.ComputeManifest{
				ID:       id,
				Tags:     maps.Clone(node.Tags),
				Evidence: node.Evidence.Clone(),
			})
		}
	}

	return list
}

type routingInfoWithID struct {
	id   uuid.UUID
	info *agent.RoutingInfo
}

func (r *routingSet) queryRoutingInfoForCandidates(candidates []api.ComputeCandidate) []routingInfoWithID {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]routingInfoWithID, 0, len(candidates))
	for _, candidate := range candidates {
		info, ok := r.nodes[candidate.ID]
		if !ok {
			continue
		}
		out = append(out, routingInfoWithID{
			id:   candidate.ID,
			info: info,
		})
	}
	return out
}
