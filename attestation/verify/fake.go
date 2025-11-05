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
//go:build include_fake_attestation

package verify

import (
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/google/go-tpm/tpm2"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	cstpm "github.com/openpcc/openpcc/tpm"
	tpmhpke "github.com/openpcc/openpcc/tpm/hpke"
)

type FakeVerifier struct {
	sharedSecret []byte
}

func NewFakeVerifier(secret []byte) Verifier {
	return &FakeVerifier{
		sharedSecret: secret,
	}
}

func (v *FakeVerifier) VerifyComputeNode(ctx context.Context, evidence ev.SignedEvidenceList) (*ev.ComputeData, error) {
	if len(evidence) != 5 {
		return nil, fmt.Errorf("expected 5 pieces of evidence, got %d", len(evidence))
	}

	// note: we don't verify the ak at all. Entirely unsafe.

	// Piece 1: TPMTPublic of the AK.
	akPublicEvidence := evidence[0]
	akTPMPTPublic, err := tpm2.Unmarshal[tpm2.TPMTPublic](akPublicEvidence.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ak: %w", err)
	}

	akPublicKey, err := cstpm.Pub(akTPMPTPublic)
	if err != nil {
		return nil, fmt.Errorf("failed convert tpmpt to get ak public key: %w", err)
	}
	akPublicKeyRSA, ok := akPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ak to be an rsa key, got %T", akPublicKey)
	}

	// Piece 2: REK Creation.
	certifyCreationResponse, err := REKCreation(ctx, akPublicKeyRSA, evidence[1])
	if err != nil {
		return nil, fmt.Errorf("failed to verify REK creation: %w", err)
	}

	tpmuAttest, err := certifyCreationResponse.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to get rek creation response contents: %w", err)
	}

	tpmsCreationInfo, err := tpmuAttest.Attested.Creation()
	if err != nil {
		return nil, fmt.Errorf("failed to parse REK creation info: %w", err)
	}

	// Piece 3: TPM Quote.
	validatedPCRValues, err := TPMQuote(ctx, akPublicKeyRSA, evidence[2])
	if err != nil {
		return nil, fmt.Errorf("failed to validate tpm quote: %w", err)
	}

	// Piece 4: TPMTPublic of the REK.
	err = TPMT(tpmsCreationInfo.ObjectName, evidence[3], *validatedPCRValues)
	if err != nil {
		return nil, fmt.Errorf("failed to verify TPMT public key: %w", err)
	}

	tpmtPublic, err := tpm2.Unmarshal[tpm2.TPMTPublic](evidence[3].Data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal TPMT public key: %w", err)
	}

	// Piece 5: The signed data from the fake attestor.
	calcSig, err := sign(v.sharedSecret, evidence[4].Data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign evidence: %w", err)
	}
	if !hmac.Equal(evidence[4].Signature, calcSig) {
		return nil, errors.New("incorrect signature on evidence")
	}

	// Convert this public key to the expected format for the HPKE KEM
	rekECCPublicKey, err := tpmhpke.Pub(tpmtPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to cast rek public key to ECC: %w", err)
	}

	nodePubKeyB, err := rekECCPublicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to bytes: %w", err)
	}

	return &ev.ComputeData{
		KEM:       hpke.KEM_P256_HKDF_SHA256,
		KDF:       hpke.KDF_HKDF_SHA256,
		AEAD:      hpke.AEAD_AES128GCM,
		PublicKey: nodePubKeyB,
	}, nil
}

func sign(secret []byte, elements ...[]byte) ([]byte, error) {
	mac := hmac.New(sha256.New, secret)
	for i, element := range elements {
		_, err := mac.Write(element)
		if err != nil {
			return nil, fmt.Errorf("failed to write %d to mac: %w", i, err)
		}
	}

	return mac.Sum(nil), nil
}
