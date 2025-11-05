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
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	pb "github.com/openpcc/openpcc/gen/protos/router"
	"github.com/openpcc/openpcc/uuidv7"
	"google.golang.org/protobuf/proto"
)

// EncapsulatedKeyHeader is the header used to forward the encapsulated key to the compute node.
const EncapsulatedKeyHeader = "X-Encapsulated-Key"

// ComputeRequestInfo contains all the data required for the router to make a routing decision.
//
// This is a struct and not a slice as we'll add more fields when we implement collaborative node selection.
type ComputeRequestInfo struct {
	Candidates []ComputeCandidate
}

func (i *ComputeRequestInfo) UnmarshalProto(pbi *pb.ComputeRequestInfo) error {
	pbCandidates := pbi.GetCandidates()
	if len(pbCandidates) == 0 {
		return errors.New("need at least one candidate, got zero")
	}

	candidates := make([]ComputeCandidate, 0, len(pbCandidates))
	for i, pbCandidate := range pbCandidates {
		candidate := ComputeCandidate{}
		err := candidate.UnmarshalProto(pbCandidate)
		if err != nil {
			return fmt.Errorf("failed to unmarshal candidate protobuf %d: %w", i, err)
		}
		candidates = append(candidates, candidate)
	}

	i.Candidates = candidates

	return nil
}

func (i *ComputeRequestInfo) MarshalProto() *pb.ComputeRequestInfo {
	pbi := &pb.ComputeRequestInfo{}

	pbCandidates := make([]*pb.ComputeCandidate, 0, len(i.Candidates))
	for _, candidate := range i.Candidates {
		pbCandidates = append(pbCandidates, candidate.MarshalProto())
	}

	pbi.SetCandidates(pbCandidates)

	return pbi
}

func (i *ComputeRequestInfo) MarshalBinary() ([]byte, error) {
	return proto.Marshal(i.MarshalProto())
}

func (i *ComputeRequestInfo) UnmarshalBinary(data []byte) error {
	pbc := &pb.ComputeRequestInfo{}
	err := proto.Unmarshal(data, pbc)
	if err != nil {
		return err
	}
	return i.UnmarshalProto(pbc)
}

func (i *ComputeRequestInfo) MarshalText() ([]byte, error) {
	b, err := i.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

func (i *ComputeRequestInfo) UnmarshalText(p []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(p))
	if err != nil {
		return err
	}

	return i.UnmarshalBinary(b)
}

type ComputeCandidate struct {
	ID uuid.UUID
	// EncapsulatedKey is the encapsulated Data Encryption Key (DEK).
	EncapsulatedKey []byte
}

func (c *ComputeCandidate) UnmarshalProto(pbc *pb.ComputeCandidate) error {
	id, err := uuidv7.Parse(pbc.GetId())
	if err != nil {
		return fmt.Errorf("failed to parse uuid: %w", err)
	}

	encapKey := pbc.GetEncapsulatedKey()
	if len(encapKey) == 0 {
		return errors.New("missing encapsulated key")
	}

	// non-legacy mode
	c.ID = id
	c.EncapsulatedKey = encapKey

	return nil
}

func (c *ComputeCandidate) MarshalProto() *pb.ComputeCandidate {
	pbc := &pb.ComputeCandidate{}

	pbc.SetId(c.ID.String())
	pbc.SetEncapsulatedKey(c.EncapsulatedKey)

	return pbc
}

func (c *ComputeCandidate) MarshalBinary() ([]byte, error) {
	return proto.Marshal(c.MarshalProto())
}

func (c *ComputeCandidate) UnmarshalBinary(data []byte) error {
	pbc := &pb.ComputeCandidate{}
	err := proto.Unmarshal(data, pbc)
	if err != nil {
		return err
	}
	return c.UnmarshalProto(pbc)
}

func (c *ComputeCandidate) CopyKeysToHeader(h http.Header) {
	h.Set(
		EncapsulatedKeyHeader,
		base64.StdEncoding.EncodeToString(c.EncapsulatedKey),
	)
}
