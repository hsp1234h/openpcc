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
	"testing"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/google/go-tpm/tpmutil"

	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"
	cstpm "github.com/openpcc/openpcc/tpm"
	"github.com/stretchr/testify/require"
)

func TestTPMTPublicAttestor_Success(t *testing.T) {
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

	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{},
	}

	createSigningCommand := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      public,
		CreationPCR:   pcrSelection,
	}
	createSigningResponse, err := createSigningCommand.Execute(thetpm)

	require.NoError(t, err)

	attestor := attest.NewTPMTPublicAttestor(thetpm, tpmutil.Handle(createSigningResponse.ObjectHandle), evidence.TpmtPublic)

	se, err := attestor.CreateSignedEvidence(t.Context())

	require.NoError(t, err)
	require.NotNil(t, se)
}

func TestTPMTPublicAttestor_FailureBadHandle(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	require.NoError(t, err)

	attestor := attest.NewTPMTPublicAttestor(thetpm, tpmutil.Handle(0x81000000), evidence.TpmtPublic)

	se, err := attestor.CreateSignedEvidence(t.Context())

	require.Errorf(t, err, "failed to read public: %w")
	require.Nil(t, se)
}

func TestVerifyTPMT_Success(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})
	desiredPcrValues := map[uint32][]byte{
		0: make([]byte, 32),
	}

	policyDigest, err := cstpm.GetSoftwarePCRPolicyDigest(desiredPcrValues)

	require.NoError(t, err)

	public := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: *policyDigest,
		},
	}

	name, err := tpm2.ObjectName(&public)
	require.NoError(t, err)

	se := &evidence.SignedEvidencePiece{
		Type:      evidence.TpmtPublic,
		Data:      tpm2.Marshal(public),
		Signature: name.Buffer,
	}

	err = verify.TPMT(*name, se, evidence.PCRValues{Values: desiredPcrValues})

	require.NoError(t, err)
}

func TestVerifyTPMT_FailureBadObjectName(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	desiredPcrValues := map[uint32][]byte{
		0: make([]byte, 32),
	}
	policyDigest, err := cstpm.GetSoftwarePCRPolicyDigest(desiredPcrValues)

	require.NoError(t, err)

	desiredPcrValues2 := map[uint32][]byte{
		1: make([]byte, 32),
	}
	policyDigest2, err := cstpm.GetSoftwarePCRPolicyDigest(desiredPcrValues2)

	require.NoError(t, err)

	public := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: *policyDigest,
		},
	}

	public2 := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: *policyDigest2,
		},
	}

	name, err := tpm2.ObjectName(&public)
	require.NoError(t, err)

	name2, err := tpm2.ObjectName(&public2)
	require.NoError(t, err)

	se := &evidence.SignedEvidencePiece{
		Type:      evidence.TpmtPublic,
		Data:      tpm2.Marshal(public),
		Signature: name.Buffer,
	}

	err = verify.TPMT(*name2, se, evidence.PCRValues{Values: desiredPcrValues})

	require.ErrorContains(t, err, "certified name does not match expected name")

	se = &evidence.SignedEvidencePiece{
		Type:      evidence.TpmtPublic,
		Data:      tpm2.Marshal(public2),
		Signature: name.Buffer,
	}

	err = verify.TPMT(*name2, se, evidence.PCRValues{Values: desiredPcrValues2})

	require.NoError(t, err)
}
