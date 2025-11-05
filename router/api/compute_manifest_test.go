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
	ev "github.com/openpcc/openpcc/attestation/evidence"
	pb "github.com/openpcc/openpcc/gen/protos/router"
	api "github.com/openpcc/openpcc/router/api"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/require"
)

func TestComputeManifestMarshalUnmarshalProto(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pbm := &pb.ComputeManifest{}
		pbm.SetId(uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f").String())
		pbm.SetTags([]string{"v1.0.2", "llm", "model=llama3.2:1b"})

		evidence := newEvidenceList()
		pbm.SetEvidence(evidence.MarshalProto())

		got := &api.ComputeManifest{}
		err := got.UnmarshalProto(pbm)
		require.NoError(t, err)

		want := &api.ComputeManifest{
			ID: uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f"),
			Tags: map[string]struct{}{
				"v1.0.2":            {},
				"llm":               {},
				"model=llama3.2:1b": {},
			},
			Evidence: evidence,
		}

		require.Equal(t, want, got)

		// check again but with non-hardcoded pb
		pbm = got.MarshalProto()
		err = got.UnmarshalProto(pbm)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	failTests := map[string]func(*pb.ComputeManifest){
		"fail, invalid UUID": func(cn *pb.ComputeManifest) {
			cn.SetId("test")
		},
		"fail, invalid UUID version": func(cn *pb.ComputeManifest) {
			id := uuid.Must(uuid.NewUUID()) // v1 uuid.
			cn.SetId(id.String())
		},
		"fail, no tags": func(cn *pb.ComputeManifest) {
			cn.SetTags([]string{})
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			pbm := &pb.ComputeManifest{}
			pbm.SetId(uuidv7.MustNew().String())
			evidence := newEvidenceList()
			pbm.SetEvidence(evidence.MarshalProto())

			tc(pbm)

			m := &api.ComputeManifest{}
			err := m.UnmarshalProto(pbm)
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
