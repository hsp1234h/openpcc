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

package evidence

import (
	"bytes"
	"testing"

	pb "github.com/openpcc/openpcc/gen/protos/evidence"
	"github.com/stretchr/testify/require"
)

func createProto(_type int, data []byte, signature []byte) *pb.SignedEvidencePiece {
	pbsep := &pb.SignedEvidencePiece{}

	pbsep.SetType(1)
	pbsep.SetData(data)
	pbsep.SetSignature(signature)

	return pbsep
}

func TestSignedEvidencePiece_MarshalProto(t *testing.T) {
	tests := []struct {
		name string
		sep  *SignedEvidencePiece
		want *pb.SignedEvidencePiece
	}{
		{
			name: "basic marshaling",
			sep: &SignedEvidencePiece{
				Type:      1,
				Data:      []byte("test-data"),
				Signature: []byte("test-signature"),
			},
			want: createProto(1, []byte("test-data"), []byte("test-signature")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.sep.MarshalProto()

			if got.GetType() != tt.want.GetType() {
				t.Errorf("MarshalProto().Type = %v, want %v", got.GetType(), tt.want.GetType())
			}
			if !bytes.Equal(got.GetData(), tt.want.GetData()) {
				t.Errorf("MarshalProto().Data = %v, want %v", got.GetData(), tt.want.GetData())
			}
			if !bytes.Equal(got.GetSignature(), tt.want.GetSignature()) {
				t.Errorf("MarshalProto().Signature = %v, want %v", got.GetSignature(), tt.want.GetSignature())
			}
		})
	}
}

func TestSignedEvidencePieceFromProto(t *testing.T) {
	tests := []struct {
		name  string
		pbsep *pb.SignedEvidencePiece
		want  *SignedEvidencePiece
	}{
		{
			name:  "basic unmarshaling",
			pbsep: createProto(1, []byte("test-data"), []byte("test-signature")),
			want: &SignedEvidencePiece{
				Type:      1,
				Data:      []byte("test-data"),
				Signature: []byte("test-signature"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got SignedEvidencePiece
			err := got.UnmarshalProto(tt.pbsep)
			require.NoError(t, err)

			if got.Type != tt.want.Type {
				t.Errorf("SignedEvidencePieceFromProto().Type = %v, want %v", got.Type, tt.want.Type)
			}
			if !bytes.Equal(got.Data, tt.want.Data) {
				t.Errorf("SignedEvidencePieceFromProto().Data = %v, want %v", got.Data, tt.want.Data)
			}
			if !bytes.Equal(got.Signature, tt.want.Signature) {
				t.Errorf("SignedEvidencePieceFromProto().Signature = %v, want %v", got.Signature, tt.want.Signature)
			}
		})
	}
}
