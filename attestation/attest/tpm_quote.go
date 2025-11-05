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

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	cstpm "github.com/openpcc/openpcc/tpm"
)

type TPMQuoteAttestor struct {
	tpm                  transport.TPM
	attestationKeyHandle tpmutil.Handle
	pcrIndices           []uint
}

func NewTPMQuoteAttestor(
	tpm transport.TPM,
	attestationKeyHandle tpmutil.Handle,
) *TPMQuoteAttestor {
	return &TPMQuoteAttestor{
		tpm:                  tpm,
		attestationKeyHandle: attestationKeyHandle,
		pcrIndices:           evidence.AttestPCRSelection,
	}
}

func (*TPMQuoteAttestor) Name() string {
	return "TPMQuoteAttestor"
}

func (a *TPMQuoteAttestor) CreateSignedEvidence(_ context.Context) (*evidence.SignedEvidencePiece, error) {
	pcrSelectionBytes := tpm2.PCClientCompatible.PCRs(evidence.AttestPCRSelection...)

	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				PCRSelect: pcrSelectionBytes,
				Hash:      tpm2.TPMAlgSHA256,
			},
		},
	}

	readPublicRequest := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(a.attestationKeyHandle),
	}

	readPublicResponse, err := readPublicRequest.Execute(a.tpm)

	if err != nil {
		return nil, err
	}

	quoteRequest := tpm2.Quote{
		SignHandle: tpm2.NamedHandle{
			Handle: readPublicRequest.ObjectHandle,
			Name:   readPublicResponse.Name,
		},
		PCRSelect: pcrSelection,
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
	}

	quoteResponse, err := quoteRequest.Execute(a.tpm)

	if err != nil {
		return nil, err
	}

	pcrValues, err := cstpm.PCRRead(a.tpm, evidence.AttestPCRSelection)

	if err != nil {
		return nil, err
	}

	tpmst, err := quoteResponse.Quoted.Contents()

	if err != nil {
		return nil, err
	}
	tpmQuoteAttestation := evidence.TPMQuoteAttestation{
		PCRValues:        &evidence.PCRValues{Values: pcrValues},
		TmpstAttestQuote: tpm2.Marshal(tpmst),
	}

	tpmQuoteAttestationBytes, err := tpmQuoteAttestation.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &evidence.SignedEvidencePiece{
		Type:      evidence.TpmQuote,
		Data:      tpmQuoteAttestationBytes,
		Signature: tpm2.Marshal(quoteResponse.Signature),
	}, nil
}
