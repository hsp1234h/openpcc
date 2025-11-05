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

package router_test

import (
	"testing"

	"github.com/google/uuid"
	pb "github.com/openpcc/openpcc/gen/protos/router/cluster"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/router"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/router/health"
	"github.com/openpcc/openpcc/router/state"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestClusterMemberPeerJoinAndLeave(t *testing.T) {
	t.Run("added to peers", func(t *testing.T) {
		meta := &pb.RouterNodeMeta{}
		meta.SetType(pb.RouterNodeMetaType_RouterV2)

		b, err := proto.Marshal(meta)
		require.NoError(t, err)

		member, broadcaster := newClusterMember(t)

		require.Equal(t, map[uuid.UUID]struct{}{
			test.DeterministicV7UUID(0): {},
		}, member.QueryRouters(t.Context()))

		// join
		member.HandleNodeJoin(t.Context(), test.DeterministicV7UUID(1), b)

		require.Equal(t, map[uuid.UUID]struct{}{
			test.DeterministicV7UUID(0): {},
			test.DeterministicV7UUID(1): {},
		}, member.QueryRouters(t.Context()))

		// leave
		member.HandleNodeLeave(t.Context(), test.DeterministicV7UUID(1), b)

		require.Equal(t, map[uuid.UUID]struct{}{
			test.DeterministicV7UUID(0): {},
		}, member.QueryRouters(t.Context()))
		broadcaster.requireNoBroadcast(t)
	})

	t.Run("self is ignored", func(t *testing.T) {
		// shouldn't happen but just to be sure.
		meta := &pb.RouterNodeMeta{}
		meta.SetType(pb.RouterNodeMetaType_RouterV2)

		b, err := proto.Marshal(meta)
		require.NoError(t, err)

		member, broadcaster := newClusterMember(t)

		require.Equal(t, map[uuid.UUID]struct{}{
			test.DeterministicV7UUID(0): {},
		}, member.QueryRouters(t.Context()))

		// join
		member.HandleNodeJoin(t.Context(), test.DeterministicV7UUID(0), b)

		require.Equal(t, map[uuid.UUID]struct{}{
			test.DeterministicV7UUID(0): {},
		}, member.QueryRouters(t.Context()))

		// leave
		member.HandleNodeLeave(t.Context(), test.DeterministicV7UUID(0), b)

		require.Equal(t, map[uuid.UUID]struct{}{
			test.DeterministicV7UUID(0): {},
		}, member.QueryRouters(t.Context()))
		broadcaster.requireNoBroadcast(t)
	})

	t.Run("invalid metadata, not added as peer", func(t *testing.T) {
		member, broadcaster := newClusterMember(t)

		routers := member.QueryRouters(t.Context())
		require.Equal(t, map[uuid.UUID]struct{}{
			test.DeterministicV7UUID(0): {},
		}, routers)

		member.HandleNodeJoin(t.Context(), test.DeterministicV7UUID(1), []byte{}) // empty bytes

		require.Equal(t, map[uuid.UUID]struct{}{
			test.DeterministicV7UUID(0): {},
		}, member.QueryRouters(t.Context()))
		broadcaster.requireNoBroadcast(t)
	})

	t.Run("v1 routers, not added as peer", func(t *testing.T) {
		meta := &pb.RouterNodeMeta{}
		meta.SetType(pb.RouterNodeMetaType_RouterV1)

		b, err := proto.Marshal(meta)
		require.NoError(t, err)

		member, broadcaster := newClusterMember(t)

		require.Equal(t, map[uuid.UUID]struct{}{
			test.DeterministicV7UUID(0): {},
		}, member.QueryRouters(t.Context()))

		member.HandleNodeJoin(t.Context(), test.DeterministicV7UUID(1), b)

		require.Equal(t, map[uuid.UUID]struct{}{
			test.DeterministicV7UUID(0): {},
		}, member.QueryRouters(t.Context()))
		broadcaster.requireNoBroadcast(t)
	})
}

func TestClusterMemberHandleMessage(t *testing.T) {
	t.Run("node event message", func(t *testing.T) {
		member, broadcaster := newClusterMember(t)

		ev := newNodeEvent(t, test.DeterministicV7UUID(0), "http://127.0.0.1")

		msg := &pb.RouterNodeMessage{}
		msg.SetNodeEvent(ev.MarshalProto())
		b, err := proto.Marshal(msg)
		require.NoError(t, err)

		requireRouterState(t, &state.Router{}, member.ReadState(t.Context()))

		member.HandleMessage(t.Context(), b)

		requireRouterState(t, &state.Router{
			Agents: map[uuid.UUID]*state.Agent{
				test.DeterministicV7UUID(0): {
					LastEventIndex:     ev.EventIndex,
					LastEventTimestamp: ev.Timestamp,
					RoutingInfo:        ev.Heartbeat.RoutingInfo,
				},
			},
		}, member.ReadState(t.Context()))
		broadcaster.requireNoBroadcast(t)
	})

	t.Run("healthcheck message", func(t *testing.T) {
		member, broadcaster := newClusterMember(t)

		check := healthcheck(0)

		msg := &pb.RouterNodeMessage{}
		msg.SetHealthcheck(check.MarshalProto())
		b, err := proto.Marshal(msg)
		require.NoError(t, err)

		requireRouterState(t, &state.Router{}, member.ReadState(t.Context()))

		member.HandleMessage(t.Context(), b)

		requireRouterState(t, &state.Router{
			Health: map[uuid.UUID]*state.NodeHealth{
				check.NodeID: {
					History: health.History{
						healthcheck(0),
					},
				},
			},
		}, member.ReadState(t.Context()))
		broadcaster.requireNoBroadcast(t)
	})

	t.Run("unknown message is ignored", func(t *testing.T) {
		member, broadcaster := newClusterMember(t)

		msg := &pb.RouterNodeMessage{}
		b, err := proto.Marshal(msg)
		require.NoError(t, err)

		requireRouterState(t, &state.Router{}, member.ReadState(t.Context()))

		member.HandleMessage(t.Context(), b)

		requireRouterState(t, &state.Router{}, member.ReadState(t.Context()))
		broadcaster.requireNoBroadcast(t)
	})

	t.Run("invalid message is ignored", func(t *testing.T) {
		member, broadcaster := newClusterMember(t)

		requireRouterState(t, &state.Router{}, member.ReadState(t.Context()))

		member.HandleMessage(t.Context(), []byte("abc"))

		requireRouterState(t, &state.Router{}, member.ReadState(t.Context()))
		broadcaster.requireNoBroadcast(t)
	})
}

func TestClusterMemberHandleState(t *testing.T) {
	t.Run("ok, router state", func(t *testing.T) {
		member, broadcaster := newClusterMember(t)

		pba := &pb.AgentState{}
		pba.SetLastEventIndex(10)
		pba.SetLastEventTimestamp(timestamppb.New(timestamp(0)))

		his := health.History{
			healthcheck(0),
		}
		pbnh := &pb.NodeHealthState{}
		pbnh.SetHistory(his.MarshalProto())

		pbr := &pb.RouterState{}
		pbr.SetAgents(map[string]*pb.AgentState{
			"01954bd0-f3c3-740e-b149-ad06ad1cebf6": pba,
		})
		pbr.SetNodeHealth(map[string]*pb.NodeHealthState{
			"01954bd0-f3c3-740e-b149-ad06ad1cebf6": pbnh,
		})

		b, err := proto.Marshal(pbr)
		require.NoError(t, err)

		requireRouterState(t, &state.Router{}, member.ReadState(t.Context()))

		member.HandleState(t.Context(), b)

		requireRouterState(t, &state.Router{
			Agents: map[uuid.UUID]*state.Agent{
				uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
					LastEventIndex:     10,
					LastEventTimestamp: timestamp(0),
				},
			},
			Health: map[uuid.UUID]*state.NodeHealth{
				uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"): {
					History: health.History{
						healthcheck(0),
					},
				},
			},
		}, member.ReadState(t.Context()))

		broadcaster.requireNoBroadcast(t)
	})

	t.Run("ok, invalid state", func(t *testing.T) {
		member, broadcaster := newClusterMember(t)

		requireRouterState(t, &state.Router{}, member.ReadState(t.Context()))

		member.HandleMessage(t.Context(), []byte("abc"))

		requireRouterState(t, &state.Router{}, member.ReadState(t.Context()))
		broadcaster.requireNoBroadcast(t)
	})
}

func TestClusterMemberAddNodeEvent(t *testing.T) {
	member, broadcaster := newClusterMember(t)
	ev := newNodeEvent(t, test.DeterministicV7UUID(0), "http://127.0.0.1")

	require.Len(t, broadcaster.lastMessage, 0)

	member.AddNodeEvent(t.Context(), ev)
	requireRouterState(t, &state.Router{
		Agents: map[uuid.UUID]*state.Agent{
			ev.NodeID: {
				LastEventIndex:     ev.EventIndex,
				LastEventTimestamp: ev.Timestamp,
				RoutingInfo:        ev.Heartbeat.RoutingInfo,
			},
		},
	}, member.ReadState(t.Context()))

	gotPB := &pb.RouterNodeMessage{}
	err := proto.Unmarshal(broadcaster.lastMessage, gotPB)
	require.NoError(t, err)
	require.True(t, gotPB.HasNodeEvent())

	got := &agent.NodeEvent{}
	err = got.UnmarshalProto(gotPB.GetNodeEvent())
	require.NoError(t, err)
	require.Equal(t, ev, got)
}

func TestClusterMemberAddHealthCheck(t *testing.T) {
	member, broadcaster := newClusterMember(t)
	check := healthcheck(0)

	require.Len(t, broadcaster.lastMessage, 0)

	member.AddHealthcheck(t.Context(), check)

	requireRouterState(t, &state.Router{
		Health: map[uuid.UUID]*state.NodeHealth{
			check.NodeID: {
				History: health.History{check},
			},
		},
	}, member.ReadState(t.Context()))

	gotPB := &pb.RouterNodeMessage{}
	err := proto.Unmarshal(broadcaster.lastMessage, gotPB)
	require.NoError(t, err)
	require.True(t, gotPB.HasHealthcheck())

	got := health.Check{}
	err = got.UnmarshalProto(gotPB.GetHealthcheck())
	require.NoError(t, err)
	require.Equal(t, check, got)
}

func newClusterMember(t *testing.T) (*router.ClusterMember, *testBroadcaster) {
	t.Helper()

	broadcaster := &testBroadcaster{}
	rtr := router.New(test.DeterministicV7UUID(0), &relaxedNodeEvaluator{})
	m := router.NewClusterMember(rtr)
	m.Broadcaster(broadcaster)
	return m, broadcaster
}

func requireRouterState(t *testing.T, want *state.Router, gotBytes []byte) {
	t.Helper()

	got := &state.Router{}
	err := got.UnmarshalBinary(gotBytes)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

type testBroadcaster struct {
	lastMessage []byte
}

func (b *testBroadcaster) requireNoBroadcast(t *testing.T) {
	require.Len(t, b.lastMessage, 0)
}

func (b *testBroadcaster) BroadcastMessage(msg []byte) {
	b.lastMessage = msg
}
