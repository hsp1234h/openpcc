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
	"log/slog"
	"net/url"

	"github.com/google/uuid"
	clusterpb "github.com/openpcc/openpcc/gen/protos/router/cluster"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/router/health"
	"github.com/openpcc/openpcc/router/state"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/protobuf/proto"
)

type MessageBroadcaster interface {
	BroadcastMessage(msg []byte)
}

// ClusterMember wraps a router and runs it as part of a gossip cluster.
type ClusterMember struct {
	*Router

	// broadcaster is used to broadcast notifications to the rest of the
	// cluster when this member receives entirely new data.
	broadcaster MessageBroadcaster

	// routerRing tracks all known router nodes in the cluster, including
	// the wrapped router. Used to spread the responsibility of health
	// checking compute nodes, so not all of the compute nodes get hit by
	// all of the routers.
	routerRing *ring
}

func NewClusterMember(r *Router) *ClusterMember {
	// create the router ring and add the router.
	routerRing := newRing()
	routerRing.addRouter(r.ID())

	return &ClusterMember{
		Router:     r,
		routerRing: routerRing,
	}
}

func (m *ClusterMember) Broadcaster(b MessageBroadcaster) {
	m.broadcaster = b
}

func (m *ClusterMember) ReadState(ctx context.Context) []byte {
	ctx, span := otelutil.Tracer.Start(ctx, "router.ClusterMember.ReadState")
	defer span.End()

	var (
		b   []byte
		err error
	)
	m.Router.ReadState(ctx, func(state *state.Router) {
		b, err = state.MarshalBinary()
	})

	if err != nil {
		slog.Error("failed to marshal router state to binary", "error", err)
		return nil
	}

	return b
}

func (m *ClusterMember) HandleState(ctx context.Context, data []byte) {
	ctx, span := otelutil.Tracer.Start(ctx, "router.ClusterMember.HandleState")
	defer span.End()

	s := &state.Router{}
	err := s.UnmarshalBinary(data)
	if err != nil {
		slog.Error("failed to unmarshal router state from binary", "error", err)
		return
	}

	m.MergeState(ctx, s)
}

func (m *ClusterMember) HandleMessage(ctx context.Context, b []byte) {
	ctx, span := otelutil.Tracer.Start(ctx, "router.ClusterMember.HandleMessage")
	defer span.End()

	msg := &clusterpb.RouterNodeMessage{}
	err := proto.Unmarshal(b, msg)
	if err != nil {
		slog.Error("failed to unmarshal cluster message", "error", err)
		return
	}

	switch {
	case msg.HasNodeEvent():
		ev := &agent.NodeEvent{}
		err := ev.UnmarshalProto(msg.GetNodeEvent())
		if err != nil {
			slog.Error("failed to unmarshal node event", "error", err)
			return
		}
		// call the underlying AddNodeEvent so we don't end up emitting an event.
		m.Router.AddNodeEvent(ctx, ev)
	case msg.HasHealthcheck():
		check := health.Check{}
		err := check.UnmarshalProto(msg.GetHealthcheck())
		if err != nil {
			slog.Error("failed to unmarshal node event", "error", err)
			return
		}
		// call the underlying AddHealthCheck so we don't end up emitting an event.
		m.Router.AddHealthcheck(ctx, check)
	default:
		slog.Warn("message received without payload")
		return
	}
}

func (m *ClusterMember) HandleNodeJoin(ctx context.Context, id uuid.UUID, b []byte) {
	ctx, span := otelutil.Tracer.Start(ctx, "router.ClusterMember.HandleNodeJoin")
	defer span.End()

	meta := &clusterpb.RouterNodeMeta{}
	err := proto.Unmarshal(b, meta)
	if err != nil {
		slog.Error("failed to unmarshal router node meta from protobuf", "error", err)
		return
	}

	if !meta.HasType() || meta.GetType() != clusterpb.RouterNodeMetaType_RouterV2 {
		// it's possible that we're running this member together with our older (v1)
		// cluster members, we filter these out as we consider them a separate cluster.
		return
	}

	m.addPeer(ctx, id)
	span.SetAttributes(
		attribute.String("router_id", id.String()),
		attribute.Int("router_ring_len", m.routerRing.Len()),
	)
}

func (m *ClusterMember) HandleNodeLeave(ctx context.Context, id uuid.UUID, _ []byte) {
	ctx, span := otelutil.Tracer.Start(ctx, "router.ClusterMember.HandleNodeLeave")
	defer span.End()
	m.removePeer(ctx, id)

	span.SetAttributes(
		attribute.String("router_id", id.String()),
		attribute.Int("router_ring_len", m.routerRing.Len()),
	)
}

func (m *ClusterMember) QueryRouters(ctx context.Context) map[uuid.UUID]struct{} {
	_, span := otelutil.Tracer.Start(ctx, "router.ClusterMember.QueryRouters")
	defer span.End()

	return m.routerRing.queryRouters()
}

func (m *ClusterMember) AddNodeEvent(ctx context.Context, ev *agent.NodeEvent) {
	_, span := otelutil.Tracer.Start(ctx, "router.ClusterMember.AddNodeEvent")
	defer span.End()

	// first, add the node event to the wrapped router
	m.Router.AddNodeEvent(ctx, ev)

	// then, broadcast it to the cluster
	msgPB := &clusterpb.RouterNodeMessage{}
	msgPB.SetNodeEvent(ev.MarshalProto())
	msg, err := proto.Marshal(msgPB)
	if err != nil {
		slog.Error("failed to marshal router node message for node event", "error", err)
		return
	}
	m.broadcaster.BroadcastMessage(msg)
}

func (m *ClusterMember) AddHealthcheck(ctx context.Context, check health.Check) {
	_, span := otelutil.Tracer.Start(ctx, "router.ClusterMember.AddHealthcheck")
	defer span.End()

	// first, add the healthcheck to the wrapped router.
	m.Router.AddHealthcheck(ctx, check)

	// then, broadcast it to the cluster
	msgPB := &clusterpb.RouterNodeMessage{}
	msgPB.SetHealthcheck(check.MarshalProto())
	msg, err := proto.Marshal(msgPB)
	if err != nil {
		slog.Error("failed to marshal router node message for healthcheck", "error", err)
		return
	}
	m.broadcaster.BroadcastMessage(msg)
}

func (m *ClusterMember) QueryHealthcheckTargets(ctx context.Context) (map[uuid.UUID]url.URL, int) {
	_, span := otelutil.Tracer.Start(ctx, "router.ClusterMember.QueryHealthcheckTargets")
	defer span.End()

	// query all targets from the router, then filter them through the ring to only
	// get the healthcheck targets this router is responsible for.
	targets, totalCount := m.Router.QueryHealthcheckTargets(ctx)
	localTargets := m.routerRing.queryHealthcheckURLs(m.ID(), targets)
	span.SetAttributes(
		attribute.Int("local_targets_len", len(localTargets)),
	)
	return localTargets, totalCount
}

func (m *ClusterMember) addPeer(ctx context.Context, id uuid.UUID) {
	_, span := otelutil.Tracer.Start(ctx, "router.ClusterMember.addPeer")
	defer span.End()

	// dont add self to the ring
	if m.ID() == id {
		return
	}

	m.routerRing.addRouter(id)
}

func (m *ClusterMember) removePeer(ctx context.Context, id uuid.UUID) {
	_, span := otelutil.Tracer.Start(ctx, "router.RemovePeer")
	defer span.End()

	// dont remove self from the ring
	if m.ID() == id {
		return
	}

	m.routerRing.removeRouter(id)
}
