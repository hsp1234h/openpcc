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
	"testing"

	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/verify"
	cstpm "github.com/openpcc/openpcc/tpm"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/google/go-tpm/tpmutil"

	"github.com/stretchr/testify/require"
)

func TestVerifyREKCreation_Success(t *testing.T) {
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

	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{},
	}

	createSigningCommand := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      public,
		CreationPCR:   pcrSelection,
	}
	createSigningResponse, err := createSigningCommand.Execute(thetpm)

	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}

	err = cstpm.WriteToNVRamNoAuth(
		thetpm,
		tpmutil.Handle(0x01c0000A),
		tpm2.Marshal(createSigningResponse.CreationTicket),
	)

	if err != nil {
		t.Fatalf("Failed to write creation ticket to NVram: %v", err)
	}

	err = cstpm.WriteToNVRamNoAuth(
		thetpm,
		tpmutil.Handle(0x01c0000B),
		tpm2.Marshal(createSigningResponse.CreationHash),
	)

	if err != nil {
		t.Fatalf("Failed to write creation hash to NVram: %v", err)
	}

	attestor := attest.NewCertifyREKCreationAttestor(
		thetpm,
		tpmutil.Handle(createSigningResponse.ObjectHandle),
		tpmutil.Handle(createSigningResponse.ObjectHandle),
		tpmutil.Handle(0x01c0000A),
		tpmutil.Handle(0x01c0000B),
	)

	pub, err := createSigningResponse.OutPublic.Contents()
	require.NoError(t, err)
	rsaDetail, err := pub.Parameters.RSADetail()
	require.NoError(t, err)
	rsaUnique, err := pub.Unique.RSA()
	require.NoError(t, err)
	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	signedEvidencePiece, err := attestor.CreateSignedEvidence(t.Context())
	require.NoError(t, err)

	_, err = verify.REKCreation(t.Context(), rsaPub, signedEvidencePiece)
	require.NoError(t, err)
}

func TestVerifyREKCreation_FailureWrongSigningKey(t *testing.T) {
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

	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{},
	}

	createSigningCommand := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      public,
		CreationPCR:   pcrSelection,
	}
	createSigningResponse, err := createSigningCommand.Execute(thetpm)

	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}

	err = cstpm.WriteToNVRamNoAuth(
		thetpm,
		tpmutil.Handle(0x01c0000A),
		tpm2.Marshal(createSigningResponse.CreationTicket),
	)

	if err != nil {
		t.Fatalf("Failed to write creation ticket to NVram: %v", err)
	}

	err = cstpm.WriteToNVRamNoAuth(
		thetpm,
		tpmutil.Handle(0x01c0000B),
		tpm2.Marshal(createSigningResponse.CreationHash),
	)

	if err != nil {
		t.Fatalf("Failed to write creation hash to NVram: %v", err)
	}

	attestor := attest.NewCertifyREKCreationAttestor(
		thetpm,
		tpmutil.Handle(createSigningResponse.ObjectHandle),
		tpmutil.Handle(createSigningResponse.ObjectHandle),
		tpmutil.Handle(0x01c0000A),
		tpmutil.Handle(0x01c0000B),
	)

	// Create random rsa keypair that will fail verification.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to create pubkey: %v", err)
	}

	signedEvidencePiece, err := attestor.CreateSignedEvidence(t.Context())
	require.NoError(t, err)

	result, err := verify.REKCreation(t.Context(), &privateKey.PublicKey, signedEvidencePiece)
	require.EqualError(t, err, "crypto/rsa: verification error")
	require.Nil(t, result)
}
