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

package api_test

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
	pb "github.com/openpcc/openpcc/gen/protos/router"
	test "github.com/openpcc/openpcc/inttest"
	api "github.com/openpcc/openpcc/router/api"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/require"
)

func TestComputeRequestInfoMarshalUnmarshalProto(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		candidates, pbCandidates := newCandidates(1)

		pbi := &pb.ComputeRequestInfo{}
		pbi.SetCandidates(pbCandidates)

		got := &api.ComputeRequestInfo{}
		err := got.UnmarshalProto(pbi)
		require.NoError(t, err)

		want := &api.ComputeRequestInfo{
			Candidates: candidates,
		}

		require.Equal(t, want, got)

		// check again but with non-hardcoded pb
		pbi = got.MarshalProto()
		err = got.UnmarshalProto(pbi)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	failTests := map[string]func(*pb.ComputeRequestInfo){
		"fail, nil candidates": func(pbi *pb.ComputeRequestInfo) {
			pbi.SetCandidates(nil)
		},
		"fail, no candidates": func(pbi *pb.ComputeRequestInfo) {
			pbi.SetCandidates([]*pb.ComputeCandidate{})
		},
		"fail, invalid candidate": func(pbi *pb.ComputeRequestInfo) {
			_, pbCandidates := newCandidates(1)
			pbCandidates[0].SetEncapsulatedKey(nil)
			pbi.SetCandidates(pbCandidates)
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			pbi := &pb.ComputeRequestInfo{}
			_, pbCandidates := newCandidates(1)
			pbi.SetCandidates(pbCandidates)

			tc(pbi)

			info := &api.ComputeRequestInfo{}
			err := info.UnmarshalProto(pbi)
			require.Error(t, err)
		})
	}
}

func TestComputeCandidateMarshalUnmarshalProto(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pbc := &pb.ComputeCandidate{}
		pbc.SetId(uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f").String())
		pbc.SetEncapsulatedKey(bytes.Repeat([]byte("abc"), 128))

		got := &api.ComputeCandidate{}
		err := got.UnmarshalProto(pbc)
		require.NoError(t, err)

		want := &api.ComputeCandidate{
			ID:              uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
			EncapsulatedKey: bytes.Repeat([]byte("abc"), 128),
		}

		require.Equal(t, want, got)

		// check again but with non-hardcoded pb
		pbc = got.MarshalProto()
		err = got.UnmarshalProto(pbc)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	failTests := map[string]func(*pb.ComputeCandidate){
		"fail, invalid UUID": func(c *pb.ComputeCandidate) {
			c.SetId("test")
		},
		"fail, invalid UUID version": func(pbc *pb.ComputeCandidate) {
			id := uuid.Must(uuid.NewUUID()) // v1 uuid.
			pbc.SetId(id.String())
		},
		"fail, empty EncapsulatedKey": func(pbc *pb.ComputeCandidate) {
			pbc.SetEncapsulatedKey([]byte{})
		},
		"fail, nil EncapsulatedKey": func(pbc *pb.ComputeCandidate) {
			pbc.SetEncapsulatedKey(nil)
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			pbc := &pb.ComputeCandidate{}
			pbc.SetId(uuidv7.MustNew().String())
			pbc.SetEncapsulatedKey(bytes.Repeat([]byte("abc"), 128))

			tc(pbc)

			c := &api.ComputeCandidate{}
			err := c.UnmarshalProto(pbc)
			require.Error(t, err)
		})
	}
}

func newCandidates(n int) ([]api.ComputeCandidate, []*pb.ComputeCandidate) {
	candidates := make([]api.ComputeCandidate, 0, n)
	protoBufs := make([]*pb.ComputeCandidate, 0, n)
	for i := range n {
		candidate := api.ComputeCandidate{
			ID:              test.DeterministicV7UUID(i),
			EncapsulatedKey: bytes.Repeat([]byte("abc"), 128),
		}

		candidates = append(candidates, candidate)
		protoBufs = append(protoBufs, candidate.MarshalProto())
	}

	return candidates, protoBufs
}
