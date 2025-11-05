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

	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/openpcc/openpcc/attestation/evidence"
	cstpm "github.com/openpcc/openpcc/tpm"
)

type CertifyREKCreationAttestor struct {
	tpm                     transport.TPM
	attestationKeyHandle    tpmutil.Handle
	childKeyHandle          tpmutil.Handle
	rekCreationTicketHandle tpmutil.Handle
	rekCreationHashHandle   tpmutil.Handle
}

func NewCertifyREKCreationAttestor(
	tpm transport.TPM,
	attestationKeyHandle tpmutil.Handle,
	childKeyHandle tpmutil.Handle,
	rekCreationTicketHandle tpmutil.Handle,
	rekCreationHashHandle tpmutil.Handle,
) *CertifyREKCreationAttestor {
	return &CertifyREKCreationAttestor{
		tpm:                     tpm,
		attestationKeyHandle:    attestationKeyHandle,
		childKeyHandle:          childKeyHandle,
		rekCreationTicketHandle: rekCreationTicketHandle,
		rekCreationHashHandle:   rekCreationHashHandle,
	}
}

func (*CertifyREKCreationAttestor) Name() string {
	return "CertifyREKCreationAttestor"
}

func (a *CertifyREKCreationAttestor) CreateSignedEvidence(_ context.Context) (*evidence.SignedEvidencePiece, error) {
	ticketData, err := cstpm.NVReadEXNoAuthorization(a.tpm, a.rekCreationTicketHandle)

	if err != nil {
		return nil, fmt.Errorf("failed to read NV index 0x%x: %w", a.rekCreationTicketHandle, err)
	}

	ticket, err := tpm2.Unmarshal[tpm2.TPMTTKCreation](ticketData)

	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ticket: %w", err)
	}

	hashData, err := cstpm.NVReadEXNoAuthorization(a.tpm, a.rekCreationHashHandle)

	if err != nil {
		return nil, fmt.Errorf("failed to read NV index %v: %w", a.rekCreationHashHandle, err)
	}

	hash, err := tpm2.Unmarshal[tpm2.TPM2BDigest](hashData)

	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal hash: %w", err)
	}

	certifyCreationResponse, err := cstpm.CertifyCreationKey(
		a.tpm,
		a.attestationKeyHandle,
		*ticket,
		*hash,
		a.childKeyHandle,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to certify creation of key: %w", err)
	}

	return &evidence.SignedEvidencePiece{
		Type:      evidence.CertifyRekCreation,
		Data:      tpm2.Marshal(certifyCreationResponse.CertifyInfo),
		Signature: tpm2.Marshal(certifyCreationResponse.Signature),
	}, nil
}
