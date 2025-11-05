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
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/url"

	"github.com/google/uuid"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/router/api"
	"github.com/openpcc/openpcc/router/health"
	"github.com/openpcc/openpcc/router/state"
	"go.opentelemetry.io/otel/attribute"
)

type EventHandler interface {
	NodeEvent(ctx context.Context, ev *agent.NodeEvent)
	Healthcheck(ctx context.Context, hc health.Check)
}

// Router proxies HTTP Requests to nodes in the routing set. It can be ran on
// its own or as a member in a cluster.
type Router struct {
	id uuid.UUID

	stateManager *state.Manager
	routingSet   *routingSet
}

func New(id uuid.UUID, nodeEvaluator state.NodeEvaluator) *Router {
	routingSet := newRoutingSet()
	return &Router{
		id:           id,
		stateManager: state.NewManager(nodeEvaluator, routingSet),
		routingSet:   routingSet,
	}
}

func (r *Router) ID() uuid.UUID {
	return r.id
}

func (r *Router) MergeState(ctx context.Context, rtr *state.Router) {
	ctx, span := otelutil.Tracer.Start(ctx, "router.HandlePeerState")
	defer span.End()

	r.stateManager.MergeRouterState(ctx, rtr)
	span.SetAttributes(
		attribute.Int("routing_set_len", r.routingSet.Len()),
	)
}

func (r *Router) AddHealthcheck(ctx context.Context, hc health.Check) {
	ctx, span := otelutil.Tracer.Start(ctx, "router.AddHealthcheck")
	defer span.End()

	r.stateManager.MergeHealthcheck(ctx, hc)
	span.SetAttributes(
		attribute.String("node_id", hc.NodeID.String()),
		attribute.Int("routing_set_len", r.routingSet.Len()),
	)
}

func (r *Router) AddNodeEvent(ctx context.Context, ev *agent.NodeEvent) {
	ctx, span := otelutil.Tracer.Start(ctx, "router.AddNodeEvent")
	defer span.End()

	r.stateManager.MergeNodeEvent(ctx, ev)
	span.SetAttributes(
		attribute.String("node_id", ev.NodeID.String()),
		attribute.Int("routing_set_len", r.routingSet.Len()),
	)
}

func (r *Router) QueryComputeManifests(ctx context.Context, q *api.ComputeManifestRequest) api.ComputeManifestList {
	_, span := otelutil.Tracer.Start(ctx, "router.QueryComputeManifests")
	defer span.End()
	manifests := r.routingSet.queryComputeManifests(q)
	span.SetAttributes(
		attribute.Int("manifests_len", len(manifests)),
		attribute.Int("routing_set_len", r.routingSet.Len()),
	)
	return manifests
}

// HealthcheckTargets returns the targets that this router is responsible for healthchecking.
func (r *Router) QueryHealthcheckTargets(ctx context.Context) (map[uuid.UUID]url.URL, int) {
	_, span := otelutil.Tracer.Start(ctx, "router.QueryHealthcheckTargets")
	defer span.End()

	targets := make(map[uuid.UUID]url.URL, 0)
	r.stateManager.ReadState(func(r *state.Router) {
		for id, agent := range r.Agents {
			if !agent.CanHealthcheck() {
				continue
			}
			targets[id] = agent.RoutingInfo.HealthcheckURL
		}
	})
	span.SetAttributes(
		attribute.Int("healthcheck_targets_len", len(targets)),
		attribute.Int("routing_set_len", r.routingSet.Len()),
	)
	return targets, len(targets)
}

// ReadState allows for the caller to read the state. The provided function must NOT make changes
// to the state, as this may cause the router to get out of sync with its sync.
//
// Note: The alternative would be for the state manager to return a copy, but since this method will
// usually be called to marshal the full state to a protobuf, that would result in the copying immediately
// being marshalled to a protobuf (another copy). A bit wasteful.
func (r *Router) ReadState(ctx context.Context, readFunc func(r *state.Router)) {
	if readFunc == nil {
		return
	}
	_, span := otelutil.Tracer.Start(ctx, "router.ReadState")
	defer span.End()

	r.stateManager.ReadState(readFunc)
}

func (r *Router) PickNodeFromCandidates(ctx context.Context, info api.ComputeRequestInfo) (api.ComputeCandidate, url.URL, error) {
	_, span := otelutil.Tracer.Start(ctx, "router.PickNodeFromCandidates")
	defer span.End()

	infos := r.routingSet.queryRoutingInfoForCandidates(info.Candidates)
	span.SetAttributes(
		attribute.Int("request_candidates_len", len(info.Candidates)),
		attribute.Int("found_candidates_len", len(infos)),
	)

	if len(infos) == 0 {
		return api.ComputeCandidate{}, url.URL{}, fmt.Errorf("did not find any available nodes after checking %d candidates", len(info.Candidates))
	}
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(infos))))
	if err != nil {
		return api.ComputeCandidate{}, url.URL{}, fmt.Errorf("failed to pick random number: %w", err)
	}

	i := idx.Int64()
	for _, candidate := range info.Candidates {
		if candidate.ID == infos[i].id {
			return candidate, infos[i].info.URL, nil
		}
	}
	return api.ComputeCandidate{}, url.URL{}, fmt.Errorf("did not find any available nodes after checking %d candidates", len(info.Candidates))
}
