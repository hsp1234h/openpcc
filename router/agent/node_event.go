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

package agent

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	pb "github.com/openpcc/openpcc/gen/protos/router/agent"
	"github.com/openpcc/openpcc/tags"
	"github.com/openpcc/openpcc/uuidv7"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type NodeEvent struct {
	EventIndex int64
	NodeID     uuid.UUID
	Timestamp  time.Time
	// Heartbeat is only set for heartbeat events. Heartbeat == nil for shutdown events.
	Heartbeat *Heartbeat
}

func (e *NodeEvent) IsShutdownEvent() bool {
	return e.Heartbeat == nil
}

func (e *NodeEvent) MarshalProto() *pb.NodeEvent {
	pbe := &pb.NodeEvent{}
	pbe.SetEventIndex(e.EventIndex)
	pbe.SetNodeId(e.NodeID.String())
	pbe.SetTimestamp(timestamppb.New(e.Timestamp))
	if e.Heartbeat != nil {
		pbe.SetHeartbeat(e.Heartbeat.MarshalProto())
	} else {
		pbe.SetShutdown(&pb.Shutdown{})
	}

	return pbe
}

func (e *NodeEvent) UnmarshalProto(pbe *pb.NodeEvent) error {
	eventIndex := pbe.GetEventIndex()
	if eventIndex < 0 {
		return fmt.Errorf("event index should be 0 or greater, got %d", eventIndex)
	}

	if !pbe.HasTimestamp() {
		return errors.New("missing timestamp")
	}
	timestamp := pbe.GetTimestamp().AsTime()

	id, err := uuidv7.Parse(pbe.GetNodeId())
	if err != nil {
		return fmt.Errorf("failed to parse uuid: %w", err)
	}

	var heartbeat *Heartbeat
	switch {
	case pbe.HasHeartbeat():
		heartbeat = &Heartbeat{}
		err = heartbeat.UnmarshalProto(pbe.GetHeartbeat())
		if err != nil {
			return fmt.Errorf("failed to unmarshal registration event data: %w", err)
		}
	case pbe.HasShutdown():
		// nothing to do, heartbeat == nil indicates shutdown
	default:
		return errors.New("event is missing event data")
	}

	e.EventIndex = eventIndex
	e.NodeID = id
	e.Timestamp = timestamp
	e.Heartbeat = heartbeat

	return nil
}

func (e *NodeEvent) MarshalBinary() ([]byte, error) {
	return proto.Marshal(e.MarshalProto())
}

func (e *NodeEvent) UnmarshalBinary(b []byte) error {
	pbe := &pb.NodeEvent{}
	err := proto.Unmarshal(b, pbe)
	if err != nil {
		return err
	}

	return e.UnmarshalProto(pbe)
}

type RoutingInfo struct {
	URL            url.URL
	HealthcheckURL url.URL
	Tags           tags.Tags
	Evidence       ev.SignedEvidenceList
}

func (r *RoutingInfo) MarshalProto() *pb.RoutingInfo {
	pbr := &pb.RoutingInfo{}

	pbr.SetUrl(r.URL.String())
	pbr.SetHealthcheckUrl(r.HealthcheckURL.String())
	pbr.SetTags(r.Tags.Slice())
	pbr.SetEvidence(r.Evidence.MarshalProto())

	return pbr
}

func (r *RoutingInfo) UnmarshalProto(pbr *pb.RoutingInfo) error {
	nodeURL, err := url.Parse(pbr.GetUrl())
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	if nodeURL.Scheme == "" {
		return errors.New("requires absolute URL")
	}

	healthURL, err := url.Parse(pbr.GetHealthcheckUrl())
	if err != nil {
		return fmt.Errorf("failed to parse healthcheck URL: %w", err)
	}

	if healthURL.Scheme == "" {
		return errors.New("requires absolute healthcheck URL")
	}

	tagslist, err := tags.FromSlice(pbr.GetTags())
	if err != nil {
		return fmt.Errorf("invalid tags: %w", err)
	}

	if len(tagslist) == 0 {
		return errors.New("requires at least one tag, got none")
	}

	var evidence ev.SignedEvidenceList
	err = evidence.UnmarshalProto(pbr.GetEvidence())
	if err != nil {
		return fmt.Errorf("failed to unmarshal signed evidence: %w", err)
	}

	r.URL = *nodeURL
	r.HealthcheckURL = *healthURL
	r.Tags = tagslist
	r.Evidence = evidence

	return nil
}

type Heartbeat struct {
	RoutingInfoURL *url.URL
	RoutingInfo    *RoutingInfo
}

func (h *Heartbeat) MarshalProto() *pb.Heartbeat {
	pbh := &pb.Heartbeat{}
	if h.RoutingInfoURL != nil {
		pbh.SetRoutingInfoUrl(h.RoutingInfoURL.String())
	} else {
		pbh.SetRoutingInfo(h.RoutingInfo.MarshalProto())
	}

	return pbh
}

func (h *Heartbeat) UnmarshalProto(pbh *pb.Heartbeat) error {
	if !pbh.HasRoutingInfoUrl() && !pbh.HasRoutingInfo() {
		return errors.New("heartbeat without url or info")
	}

	if pbh.HasRoutingInfoUrl() {
		return h.unmarshalRoutingInfoURLProto(pbh)
	}

	routingInfo := &RoutingInfo{}
	err := routingInfo.UnmarshalProto(pbh.GetRoutingInfo())
	if err != nil {
		return err
	}
	h.RoutingInfo = routingInfo
	return nil
}

func (h *Heartbeat) unmarshalRoutingInfoURLProto(pbh *pb.Heartbeat) error {
	routingInfoURL, err := url.Parse(pbh.GetRoutingInfoUrl())
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	if routingInfoURL.Scheme == "" {
		return errors.New("requires absolute URL")
	}

	h.RoutingInfoURL = routingInfoURL
	return nil
}
