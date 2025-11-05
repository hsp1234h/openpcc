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

package tpm

import (
	"crypto/ecdh"
	"crypto/rand"
	"math"
	"testing"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/require"
)

func TestNVReadEXNoAuthorization_ReadDataSuccess(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	testHandle := 0x0180000F

	def := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		Auth: tpm2.TPM2BAuth{
			Buffer: []byte(""),
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex: tpm2.TPMHandle(testHandle),
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					OwnerWrite: true,
					OwnerRead:  true,
					AuthWrite:  true,
					AuthRead:   true,
					NT:         tpm2.TPMNTOrdinary,
					NoDA:       true,
				},
				DataSize: 4,
			}),
	}
	if _, err := def.Execute(thetpm); err != nil {
		t.Fatalf("Calling TPM2_NV_DefineSpace: %v", err)
	}

	pub, err := def.PublicInfo.Contents()
	if err != nil {
		t.Fatalf("%v", err)
	}
	nvName, err := tpm2.NVName(pub)
	if err != nil {
		t.Fatalf("Calculating name of NV index: %v", err)
	}

	prewrite := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth([]byte{})),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: pub.NVIndex,
			Name:   *nvName,
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: []byte{0x01, 0x02, 0x03, 0x04},
		},
		Offset: 0,
	}
	_, err = prewrite.Execute(thetpm)

	require.NoError(t, err)

	bytes, err := NVReadEXNoAuthorization(thetpm, tpmutil.Handle(pub.NVIndex))

	require.NoError(t, err)

	require.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, bytes)
}

func TestNVReadEXNoAuthorization_WrongHandleFailure(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	testHandle := 0x0180000F

	_, err = NVReadEXNoAuthorization(thetpm, tpmutil.Handle(testHandle))

	require.EqualError(
		t,
		err,
		"TPM_RC_HANDLE (handle 1): the handle is not correct for the use")
}

func TestGetTPMCapability_Success(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	capability, err := GetTPMCapability(thetpm, tpm2.TPMPTNVBufferMax)

	require.NoError(t, err)
	require.NotNil(t, capability)
}

func TestGetTPMCapability_InvalidCapabilityFailure(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	_, err = GetTPMCapability(thetpm, 0xDEADBEEF)

	require.EqualError(
		t,
		err,
		"Property deadbeef not found in capability data")
}

func TestGetHandles_Success(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	handles, err := GetHandles(thetpm, tpm2.TPMHTHMACSession, 1)
	require.NoError(t, err)
	require.NotEmpty(t, handles)
	require.Len(t, handles, 1)

	handles, err = GetHandles(thetpm, tpm2.TPMHTHMACSession, 2)
	require.NoError(t, err)
	require.NotEmpty(t, handles)
	require.Len(t, handles, 2)

	handles, err = GetHandles(thetpm, tpm2.TPMHTHMACSession, uint32(math.MaxUint32))
	require.NoError(t, err)
	require.NotEmpty(t, handles)
	require.Len(t, handles, 22)
}

func TestGetHandles_InvalidTypeNoHandles(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	handles, err := GetHandles(thetpm, tpm2.TPMHT(0xBA), 1)
	require.NoError(t, err)
	require.Empty(t, handles)
}

func TestPersistObject_SuccessAndCanLoadObject(t *testing.T) {
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

	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}

	targetHandle := tpm2.TPMHandle(0x81000001)

	err = PersistObject(
		thetpm,
		tpmutil.Handle(createSigningResponse.ObjectHandle),
		tpmutil.Handle(targetHandle))

	require.NoError(t, err)

	readPublicCommand := tpm2.ReadPublic{
		ObjectHandle: targetHandle,
	}

	_, err = readPublicCommand.Execute(thetpm)

	require.NoError(t, err)
}

func TestPersistObject_FailureCannotLoadEmptyHandle(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	objectHandle := tpm2.TPMHandle(0x81000001)
	targetHandle := tpm2.TPMHandle(0x81000002)

	err = PersistObject(
		thetpm,
		tpmutil.Handle(objectHandle),
		tpmutil.Handle(targetHandle))

	require.ErrorContains(t, err, "TPM_RC_HANDLE (handle 1): the handle is not correct for the use")
}

func TestCreateAndPersistECCEncryptionKey_SuccessAndCanBeUsedForZGen(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	createPrimaryResponse, err := CreateECCPrimaryKey(thetpm)

	require.NoError(t, err)

	// The zero auth policy is the initial state for the policy authorization session.
	// This will pass if no policy evaluation commands are executed in the session.
	// The golden PCR values are going to be whatever the state of the machine is at this point
	goldenPcrValues, err := PCRRead(thetpm, []uint{
		0, 1, 2, 3, 4, 5, 7, 8, 12,
	})
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	authorizationPolicyDigest, err := GetTPMPCRPolicyDigest(
		thetpm,
		goldenPcrValues,
	)

	if err != nil {
		t.Fatalf("could not create digest: %v", err)
	}

	createResponse, loadResponse, err := CreateECCEncryptionKey(
		thetpm,
		createPrimaryResponse.ObjectHandle,
		*authorizationPolicyDigest,
	)

	require.NoError(t, err)
	require.NotNil(t, createResponse)

	// Use NIST P-256
	curve := ecdh.P256()

	// Create a Softwarre based ECDH key so that we can get some point which lies on this curve.
	// It's not really possible to put any number in here.
	swPriv, err := curve.GenerateKey(rand.Reader)
	require.NoError(t, err)
	x, y, err := tpm2.ECCPoint(swPriv.PublicKey())
	require.NoError(t, err)

	eccPoint := tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: x.FillBytes(make([]byte, 32))},
		Y: tpm2.TPM2BECCParameter{Buffer: y.FillBytes(make([]byte, 32))},
	}

	sess, sessionCleanup, err := PCRPolicySession(thetpm, goldenPcrValues)
	require.NoError(t, err)

	defer sessionCleanup()

	ecdhzgenRequest := tpm2.ECDHZGen{
		KeyHandle: tpm2.AuthHandle{
			Handle: loadResponse.ObjectHandle,
			Name:   loadResponse.Name,
			Auth:   sess,
		},
		InPoint: tpm2.New2B(eccPoint),
	}

	ecdhzgenRequestResponse, err := ecdhzgenRequest.Execute(thetpm)

	require.NoError(t, err)
	require.NotNil(t, ecdhzgenRequestResponse)
	require.NotEmpty(t, ecdhzgenRequestResponse.OutPoint.Bytes())
}

func TestCreateAndPersistECCEncryptionKey_CannotBeUsedForZGenWithPolicyMismatch(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	createPrimaryResponse, err := CreateECCPrimaryKey(thetpm)

	require.NoError(t, err)

	// We will define a nonzero auth policy. We will fail to match this
	// because we will not execute any commands in the policy session.
	nonZeroAuthPolicy := make([]byte, 32)
	for i := 0; i < len(nonZeroAuthPolicy); i++ {
		nonZeroAuthPolicy[i] = 1
	}

	createResponse, loadResponse, err := CreateECCEncryptionKey(
		thetpm,
		createPrimaryResponse.ObjectHandle,
		nonZeroAuthPolicy,
	)

	require.NoError(t, err)
	require.NotNil(t, createResponse)

	// Use NIST P-256
	curve := ecdh.P256()

	// Create a Softwarre based ECDH key so that we can get some point which lies on this curve.
	// It's not really possible to put any number in here.
	swPriv, err := curve.GenerateKey(rand.Reader)
	require.NoError(t, err)
	x, y, err := tpm2.ECCPoint(swPriv.PublicKey())
	require.NoError(t, err)

	eccPoint := tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: x.FillBytes(make([]byte, 32))},
		Y: tpm2.TPM2BECCParameter{Buffer: y.FillBytes(make([]byte, 32))},
	}

	sess, sessionCleanup, err := tpm2.PolicySession(thetpm, tpm2.TPMAlgSHA256, 32)

	require.NoError(t, err)

	defer sessionCleanup()

	ecdhzgenRequest := tpm2.ECDHZGen{
		KeyHandle: tpm2.AuthHandle{
			Handle: loadResponse.ObjectHandle,
			Name:   loadResponse.Name,
			Auth:   sess,
		},
		InPoint: tpm2.New2B(eccPoint),
	}

	ecdhzgenRequestResponse, err := ecdhzgenRequest.Execute(thetpm)

	require.Nil(t, ecdhzgenRequestResponse)
	require.ErrorContains(t, err, "TPM_RC_POLICY_FAIL")
}

func TestCertifyCreation_Success(t *testing.T) {
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
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA1,
				PCRSelect: tpm2.PCClientCompatible.PCRs(5),
			},
		},
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

	createPrimaryResponse, err := CreateECCPrimaryKey(thetpm)
	require.NoError(t, err)

	zeroAuthPolicy := make([]byte, 32)
	for i := 0; i < len(zeroAuthPolicy); i++ {
		zeroAuthPolicy[i] = 0
	}

	createResponse, loadResponse, err := CreateECCEncryptionKey(thetpm, createPrimaryResponse.ObjectHandle, zeroAuthPolicy)
	require.NoError(t, err)

	certifyCreationResponse, err := CertifyCreationKey(
		thetpm,
		tpmutil.Handle(createSigningResponse.ObjectHandle),
		createResponse.CreationTicket,
		createResponse.CreationHash,
		tpmutil.Handle(loadResponse.ObjectHandle))

	require.NoError(t, err)
	require.NotNil(t, certifyCreationResponse)
}

func TestWriteDataToNVRam_Success(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	testHandle := 0x0180000F
	// make random bytes
	data := make([]byte, 256)
	_, err = rand.Read(data)
	require.NoError(t, err)

	err = WriteToNVRamNoAuth(thetpm, tpmutil.Handle(testHandle), data)

	require.NoError(t, err)

	bytes, err := NVReadEXNoAuthorization(thetpm, tpmutil.Handle(testHandle))

	require.NoError(t, err)
	require.Equal(t, data, bytes)
}

func TestGetInUsePersistentHandles_Success(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	createPrimaryResponse, err := CreateECCPrimaryKey(thetpm)
	require.NoError(t, err)
	PersistObject(
		thetpm,
		tpmutil.Handle(createPrimaryResponse.ObjectHandle),
		tpmutil.Handle(0x81000001))
	require.NoError(t, err)

	handles, err := GetInUsePersistentHandles(thetpm)
	require.NoError(t, err)
	require.NotEmpty(t, handles)
	require.Len(t, handles, 1)
	require.Equal(t, handles[0], tpm2.TPMHandle(0x81000001))
}

func TestGetInUsePersistentHandles_NoHandles(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	handles, err := GetInUsePersistentHandles(thetpm)
	require.NoError(t, err)
	require.Empty(t, handles)
}

func TestGetInUseNVIndices_Success(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	WriteToNVRamNoAuth(thetpm, tpmutil.Handle(0x0180000F), []byte{0x01, 0x02, 0x03, 0x04})
	handles, err := GetInUseNVIndices(thetpm)
	require.NoError(t, err)
	require.Len(t, handles, 1)
	require.Equal(t, handles[0], tpm2.TPMHandle(0x0180000F))
}

func TestGetInUseNVIndices_NoHandles(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	handles, err := GetInUseNVIndices(thetpm)
	require.NoError(t, err)
	require.Empty(t, handles)
}

func TestMaybeClearPersistentHandle_SuccessClears(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	createPrimaryResponse, err := CreateECCPrimaryKey(thetpm)
	require.NoError(t, err)

	err = PersistObject(
		thetpm,
		tpmutil.Handle(createPrimaryResponse.ObjectHandle),
		tpmutil.Handle(0x81000001))

	require.NoError(t, err)

	err = MaybeClearPersistentHandle(thetpm, tpmutil.Handle(0x81000001))
	require.NoError(t, err)

	handles, err := GetInUsePersistentHandles(thetpm)
	require.NoError(t, err)
	require.Empty(t, handles)
}

func TestMaybeClearPersistentHandle_SuccessEmpty(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	err = MaybeClearPersistentHandle(thetpm, tpmutil.Handle(0x81000001))
	require.NoError(t, err)
}

func TestMaybeClearNVIndices_Success(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	WriteToNVRamNoAuth(thetpm, tpmutil.Handle(0x0180000F), []byte{0x01, 0x02, 0x03, 0x04})
	err = MaybeClearNVIndex(thetpm, tpmutil.Handle(0x0180000F))
	require.NoError(t, err)

	handles, err := GetInUseNVIndices(thetpm)
	require.NoError(t, err)
	require.Len(t, handles, 0)
}

func TestMaybeClearNVIndices_SuccessEmpty(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	err = MaybeClearNVIndex(thetpm, tpmutil.Handle(0x0180000F))
	require.NoError(t, err)
}

func TestGetSoftwarePCRPolicyDigest_Matches(t *testing.T) {
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
		0: {0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C,
			0x0D, 0x0E, 0x0F, 0x10,
			0x11, 0x12, 0x13, 0x14,
			0x15, 0x16, 0x17, 0x18,
			0x19, 0x1A, 0x1B, 0x1C,
			0x1D, 0x1E, 0x1F, 0x20},
	}

	tpmPcrPolicyDigest, err := GetTPMPCRPolicyDigest(thetpm, desiredPcrValues)
	require.NoError(t, err)

	softwarePcrPolicyDigest, err := GetSoftwarePCRPolicyDigest(desiredPcrValues)
	require.NoError(t, err)
	require.Equal(t, tpmPcrPolicyDigest, softwarePcrPolicyDigest)

	desiredPcrValues2 := map[uint32][]byte{
		0: {0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C,
			0x0D, 0x0E, 0x0F, 0x10,
			0x11, 0x12, 0x13, 0x14,
			0x15, 0x16, 0x17, 0x18,
			0x19, 0x1A, 0x1B, 0x1C,
			0x1D, 0x1E, 0x1F, 0x20},
		1: {0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C,
			0x0D, 0x0E, 0x0F, 0x10,
			0x11, 0x12, 0x13, 0x14,
			0x15, 0x16, 0x17, 0x18,
			0x19, 0x1A, 0x1B, 0x1C,
			0x1D, 0x1E, 0x1F, 0x20},
	}

	tpmPcrPolicyDigest2, err := GetTPMPCRPolicyDigest(thetpm, desiredPcrValues2)
	require.NoError(t, err)

	softwarePcrPolicyDigest2, err := GetSoftwarePCRPolicyDigest(desiredPcrValues2)
	require.NoError(t, err)
	require.Equal(t, tpmPcrPolicyDigest2, softwarePcrPolicyDigest2)

	require.NotEqual(t, tpmPcrPolicyDigest, softwarePcrPolicyDigest2)
	require.NotEqual(t, tpmPcrPolicyDigest2, softwarePcrPolicyDigest)
}
