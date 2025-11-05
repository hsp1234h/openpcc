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
package attest

import (
	"context"

	"github.com/openpcc/openpcc/attestation/evidence"

	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// TPMTPublicAttestor attests a TPMTPublic structure along with its hash,
// which is the secure cryptographic name of the object.
type TPMTPublicAttestor struct {
	tpm                transport.TPM
	targetObjectHandle tpmutil.Handle
}

func NewTPMTPublicAttestor(
	tpm transport.TPM,
	targetObjectHandle tpmutil.Handle,
) *TPMTPublicAttestor {
	return &TPMTPublicAttestor{
		tpm:                tpm,
		targetObjectHandle: targetObjectHandle,
	}
}

func (*TPMTPublicAttestor) Name() string {
	return "TPMTPublicAttestor"
}

func (a *TPMTPublicAttestor) CreateSignedEvidence(_ context.Context) (*evidence.SignedEvidencePiece, error) {
	readPublicRequest := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(a.targetObjectHandle),
	}

	readPublicResponse, err := readPublicRequest.Execute(a.tpm)

	if err != nil {
		return nil, fmt.Errorf("failed to read public: %w", err)
	}

	publicContents, err := readPublicResponse.OutPublic.Contents()

	if err != nil {
		return nil, fmt.Errorf("failed to get public contents: %w", err)
	}

	return &evidence.SignedEvidencePiece{
		Type:      evidence.TpmtPublic,
		Data:      tpm2.Marshal(publicContents),
		Signature: readPublicResponse.Name.Buffer,
	}, nil
}
