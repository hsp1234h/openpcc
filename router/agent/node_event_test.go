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

package agent_test

import (
	"bytes"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	pb "github.com/openpcc/openpcc/gen/protos/router/agent"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNodeEventMarshalUnmarshalProto(t *testing.T) {
	t.Run("ok, heartbeat with routing info", func(t *testing.T) {
		timestamp := time.Now().UTC().Round(0)
		evidence := newEvidenceList()

		pbe := &pb.NodeEvent{}
		pbe.SetNodeId(uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f").String())
		pbe.SetEventIndex(10)
		pbe.SetTimestamp(timestamppb.New(timestamp))

		pbri := &pb.RoutingInfo{}
		pbri.SetUrl("http://localhost/test")
		pbri.SetHealthcheckUrl("http://localhost/_health")
		pbri.SetTags([]string{"v1.0.2", "llm", "model=llama3.2:1b"})
		pbri.SetEvidence(evidence.MarshalProto())

		pbh := &pb.Heartbeat{}
		pbh.SetRoutingInfo(pbri)
		pbe.SetHeartbeat(pbh)

		got := &agent.NodeEvent{}
		err := got.UnmarshalProto(pbe)
		require.NoError(t, err)

		want := &agent.NodeEvent{
			NodeID:     uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
			EventIndex: 10,
			Timestamp:  timestamp,
			Heartbeat: &agent.Heartbeat{
				RoutingInfo: &agent.RoutingInfo{
					URL:            *test.Must(url.Parse("http://localhost/test")),
					HealthcheckURL: *test.Must(url.Parse("http://localhost/_health")),
					Tags: map[string]struct{}{
						"v1.0.2":            {},
						"llm":               {},
						"model=llama3.2:1b": {},
					},
					Evidence: evidence,
				},
			},
		}

		require.Equal(t, want, got)

		// check again but with non-hardcoded pb
		pbe = got.MarshalProto()
		err = got.UnmarshalProto(pbe)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("ok, heartbeat with routing info url", func(t *testing.T) {
		timestamp := time.Now().UTC().Round(0)

		pbe := &pb.NodeEvent{}
		pbe.SetNodeId(uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f").String())
		pbe.SetEventIndex(10)
		pbe.SetTimestamp(timestamppb.New(timestamp))

		pbh := &pb.Heartbeat{}
		pbh.SetRoutingInfoUrl("http://localhost/routing-info")
		pbe.SetHeartbeat(pbh)

		got := &agent.NodeEvent{}
		err := got.UnmarshalProto(pbe)
		require.NoError(t, err)

		want := &agent.NodeEvent{
			NodeID:     uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
			EventIndex: 10,
			Timestamp:  timestamp,
			Heartbeat: &agent.Heartbeat{
				RoutingInfoURL: test.Must(url.Parse("http://localhost/routing-info")),
			},
		}

		require.Equal(t, want, got)

		// check again but with non-hardcoded pb
		pbe = got.MarshalProto()
		err = got.UnmarshalProto(pbe)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("ok, shutdown", func(t *testing.T) {
		timestamp := time.Now().UTC().Round(0)

		pbe := &pb.NodeEvent{}
		pbe.SetNodeId(uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f").String())
		pbe.SetEventIndex(10)
		pbe.SetTimestamp(timestamppb.New(timestamp))
		pbe.SetShutdown(&pb.Shutdown{})

		got := &agent.NodeEvent{}
		err := got.UnmarshalProto(pbe)
		require.NoError(t, err)

		want := &agent.NodeEvent{
			NodeID:     uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
			EventIndex: 10,
			Timestamp:  timestamp,
			// No heartbeat indicates shutdown.
		}

		require.Equal(t, want, got)

		// check again but with non-hardcoded pb
		pbe = got.MarshalProto()
		err = got.UnmarshalProto(pbe)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	failTests := map[string]func(*pb.NodeEvent){
		"fail, invalid node UUID": func(pbe *pb.NodeEvent) {
			pbe.SetNodeId("test")
		},
		"fail, invalid node UUID version": func(pbe *pb.NodeEvent) {
			id := uuid.Must(uuid.NewUUID()) // v1 uuid.
			pbe.SetNodeId(id.String())
		},
		"fail, negative event index": func(pbe *pb.NodeEvent) {
			pbe.SetEventIndex(-1)
		},
		"fail, missing timestamp": func(pbe *pb.NodeEvent) {
			pbe.SetTimestamp(nil)
		},
		"fail, missing event data": func(pbe *pb.NodeEvent) {
			pbe.SetHeartbeat(nil)
			pbe.SetShutdown(nil)
		},
		"fail, invalid heartbeat event data": func(pbe *pb.NodeEvent) {
			pbe.GetHeartbeat().SetRoutingInfoUrl("://://")
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			timestamp := time.Now().UTC().Round(0)

			pbe := &pb.NodeEvent{}
			pbe.SetNodeId(uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f").String())
			pbe.SetEventIndex(10)
			pbe.SetTimestamp(timestamppb.New(timestamp))

			pbh := &pb.Heartbeat{}
			pbh.SetRoutingInfoUrl("http://localhost/routing-info")
			pbe.SetHeartbeat(pbh)

			tc(pbe)

			e := &agent.NodeEvent{}
			err := e.UnmarshalProto(pbe)
			require.Error(t, err)
		})
	}
}

func TestRoutingInfoMarshalUnmarshalProto(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		evidence := newEvidenceList()

		pbreg := &pb.RoutingInfo{}
		pbreg.SetUrl("http://localhost/test")
		pbreg.SetHealthcheckUrl("http://localhost/_health")
		pbreg.SetTags([]string{"v1.0.2", "llm", "model=llama3.2:1b"})
		pbreg.SetEvidence(evidence.MarshalProto())

		got := &agent.RoutingInfo{}
		err := got.UnmarshalProto(pbreg)
		require.NoError(t, err)

		want := &agent.RoutingInfo{
			URL:            *test.Must(url.Parse("http://localhost/test")),
			HealthcheckURL: *test.Must(url.Parse("http://localhost/_health")),
			Tags: map[string]struct{}{
				"v1.0.2":            {},
				"llm":               {},
				"model=llama3.2:1b": {},
			},
			Evidence: evidence,
		}

		require.Equal(t, want, got)

		// check again but with non-hardcoded pb
		pbreg = got.MarshalProto()
		err = got.UnmarshalProto(pbreg)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	failTests := map[string]func(*pb.RoutingInfo){
		"fail, invalid URL": func(pbr *pb.RoutingInfo) {
			pbr.SetUrl("://://")
		},
		"fail, relative URL": func(pbr *pb.RoutingInfo) {
			pbr.SetUrl("/test")
		},
		"fail, invalid healthcheck URL": func(pbr *pb.RoutingInfo) {
			pbr.SetHealthcheckUrl("://://")
		},
		"fail, relative healthcheck URL": func(pbr *pb.RoutingInfo) {
			pbr.SetHealthcheckUrl("/test")
		},
		"fail, no tags": func(pbr *pb.RoutingInfo) {
			pbr.SetTags([]string{})
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			pbr := &pb.RoutingInfo{}
			pbr.SetUrl("http://localhost/test")
			evidence := newEvidenceList()
			pbr.SetEvidence(evidence.MarshalProto())

			tc(pbr)

			r := &agent.RoutingInfo{}
			err := r.UnmarshalProto(pbr)
			require.Error(t, err)
		})
	}
}

func newEvidenceList() ev.SignedEvidenceList {
	return ev.SignedEvidenceList{
		&ev.SignedEvidencePiece{
			Type:      ev.SevSnpReport,
			Data:      bytes.Repeat([]byte("abc"), 2048),
			Signature: []byte("01234567890"),
		},
		&ev.SignedEvidencePiece{
			Type:      ev.SevSnpReport,
			Data:      bytes.Repeat([]byte("def"), 2048),
			Signature: []byte("09876543210"),
		},
	}
}
