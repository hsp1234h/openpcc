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

package attest_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/google/go-tpm/tpmutil"

	"github.com/stretchr/testify/require"
)

func TestVerifyTPMQuote_Success(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	public := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			Restricted:          true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
	})

	createSigningCommand := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      public,
	}
	createSigningResponse, err := createSigningCommand.Execute(thetpm)

	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}

	pub, err := createSigningResponse.OutPublic.Contents()
	require.NoError(t, err)
	rsaDetail, err := pub.Parameters.RSADetail()
	require.NoError(t, err)
	rsaUnique, err := pub.Unique.RSA()
	require.NoError(t, err)
	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	attestor := attest.NewTPMQuoteAttestor(thetpm, tpmutil.Handle(createSigningResponse.ObjectHandle))

	se, err := attestor.CreateSignedEvidence(t.Context())
	require.NoError(t, err)
	require.NotNil(t, se)

	_, err = verify.TPMQuote(
		t.Context(),
		rsaPub,
		se,
	)

	require.NoError(t, err)
}

func TestVerifyTPMQuote_FailureWrongSigningKey(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	// Create a key and use it to sign its own creation data
	public := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			Restricted:          true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
	})

	createSigningCommand := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      public,
	}
	createSigningResponse, err := createSigningCommand.Execute(thetpm)

	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}

	attestor := attest.NewTPMQuoteAttestor(thetpm, tpmutil.Handle(createSigningResponse.ObjectHandle))

	se, err := attestor.CreateSignedEvidence(t.Context())
	require.NoError(t, err)
	require.NotNil(t, se)

	// Create random rsa keypair that will fail verification.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to create pubkey: %v", err)
	}

	_, err = verify.TPMQuote(
		t.Context(),
		&privateKey.PublicKey,
		se,
	)
	require.EqualError(t, err, "crypto/rsa: verification error")
}

func TestVerifyTPMQuote_FailureBadPlaintextPCRValues(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	// Create a key and use it to sign its own creation data
	public := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			Restricted:          true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
	})

	createSigningCommand := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      public,
	}
	createSigningResponse, err := createSigningCommand.Execute(thetpm)

	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}

	attestor := attest.NewTPMQuoteAttestor(thetpm, tpmutil.Handle(createSigningResponse.ObjectHandle))

	se, err := attestor.CreateSignedEvidence(t.Context())
	require.NoError(t, err)
	require.NotNil(t, se)

	pub, err := createSigningResponse.OutPublic.Contents()
	require.NoError(t, err)
	rsaDetail, err := pub.Parameters.RSADetail()
	require.NoError(t, err)
	rsaUnique, err := pub.Unique.RSA()
	require.NoError(t, err)
	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	tpmQuoteProto := evidence.TPMQuoteAttestation{}

	err = tpmQuoteProto.UnmarshalBinary(se.Data)
	require.NoError(t, err)

	badHash := sha256.Sum256([]byte{0xde, 0xad, 0xbe, 0xef})
	tpmQuoteProto.PCRValues.Values[uint32(0)] = badHash[:]

	badTpmQuoteProtoBytes, err := tpmQuoteProto.MarshalBinary()
	require.NoError(t, err)
	badEvidence, err := &evidence.SignedEvidencePiece{
		Type:      evidence.TpmQuote,
		Data:      badTpmQuoteProtoBytes,
		Signature: se.Signature,
	}, nil

	require.NoError(t, err)

	_, err = verify.TPMQuote(
		t.Context(),
		rsaPub,
		badEvidence,
	)
	require.EqualError(t, err, "plaintext TPMQuoteAttestation PCR values don't match the signed data")
}
