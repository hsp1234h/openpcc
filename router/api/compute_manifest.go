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

package api

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	pb "github.com/openpcc/openpcc/gen/protos/router"
	"github.com/openpcc/openpcc/tags"
	"github.com/openpcc/openpcc/uuidv7"
	"google.golang.org/protobuf/proto"
)

// ComputeManifest is the data used by the client and router to select
// nodes to fullfil requests. A ComputeManifest is unique to a
// single boot-shutdown cycle of a compute node.
type ComputeManifest struct {
	ID       uuid.UUID
	Tags     tags.Tags
	Evidence ev.SignedEvidenceList
}

func (m *ComputeManifest) MarshalBinary() ([]byte, error) {
	return proto.Marshal(m.MarshalProto())
}

func (m *ComputeManifest) MarshalProto() *pb.ComputeManifest {
	pbm := &pb.ComputeManifest{}

	pbm.SetId(m.ID.String())
	pbm.SetEvidence(m.Evidence.MarshalProto())
	pbm.SetTags(m.Tags.Slice())

	return pbm
}

func (m *ComputeManifest) UnmarshalProto(pbm *pb.ComputeManifest) error {
	id, err := uuidv7.Parse(pbm.GetId())
	if err != nil {
		return fmt.Errorf("failed to parse uuid: %w", err)
	}

	tagslist, err := tags.FromSlice(pbm.GetTags())
	if err != nil {
		return fmt.Errorf("invalid tags: %w", err)
	}

	if len(tagslist) == 0 {
		return errors.New("requires at least one tag, got none")
	}

	var evidence ev.SignedEvidenceList
	err = evidence.UnmarshalProto(pbm.GetEvidence())
	if err != nil {
		return fmt.Errorf("failed to unmarshal signed evidence: %w", err)
	}

	m.ID = id
	m.Tags = tagslist
	m.Evidence = evidence

	return nil
}

type ComputeManifestList []ComputeManifest

func (l ComputeManifestList) MarshalBinary() ([]byte, error) {
	return proto.Marshal(l.MarshalProto())
}

func (l *ComputeManifestList) UnmarshalBinary(b []byte) error {
	pbl := &pb.ComputeManifestList{}
	err := proto.Unmarshal(b, pbl)
	if err != nil {
		return err
	}
	return l.UnmarshalProto(pbl)
}

func (l ComputeManifestList) MarshalProto() *pb.ComputeManifestList {
	pbe := &pb.ComputeManifestList{}

	out := make([]*pb.ComputeManifest, 0, len(l))
	for _, item := range l {
		out = append(out, item.MarshalProto())
	}

	pbe.SetItems(out)

	return pbe
}

func (l *ComputeManifestList) UnmarshalProto(pbl *pb.ComputeManifestList) error {
	newL := make(ComputeManifestList, 0, len(pbl.GetItems()))
	for _, pbm := range pbl.GetItems() {
		m := ComputeManifest{}
		err := m.UnmarshalProto(pbm)
		if err != nil {
			return err
		}
		newL = append(newL, m)
	}

	*l = newL
	return nil
}
