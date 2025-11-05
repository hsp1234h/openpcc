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

package hpke_test

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/google/go-tpm/tpmutil"
	cstpm "github.com/openpcc/openpcc/tpm"
	tpmHPKE "github.com/openpcc/openpcc/tpm/hpke"
	"github.com/stretchr/testify/require"
)

func TestReceiver(t *testing.T) {
	thetpm := runTPMSimulatorWhile(t)

	encryptFor := func(t *testing.T, pubKey kem.PublicKey, pt, infoSender, infoSeal []byte) ([]byte, []byte) {
		suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)

		sender, err := suite.NewSender(pubKey, infoSender)
		require.NoError(t, err)

		encapKey, sealer, err := sender.Setup(rand.Reader)
		require.NoError(t, err)

		ct, err := sealer.Seal(pt, infoSeal)
		require.NoError(t, err)

		return encapKey, ct
	}

	tests := map[string]struct {
		pt         []byte
		infoSender []byte
		infoSeal   []byte
	}{
		"ok, no info": {
			pt: []byte("hello world!"),
		},
		"ok, sender/receiver info": {
			pt:         []byte("hello world!"),
			infoSender: []byte("context 1"),
		},
		"ok, seal/open info": {
			pt:       []byte("hello world!"),
			infoSeal: []byte("context 1"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Create a TPM ECDH key with no authorization policy.
			tpmCreate := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHOwner,
				InPublic: tpm2.New2B(tpm2.TPMTPublic{
					Type:    tpm2.TPMAlgECC,
					NameAlg: tpm2.TPMAlgSHA256,
					ObjectAttributes: tpm2.TPMAObject{
						FixedTPM:             true,
						STClear:              false,
						FixedParent:          true,
						SensitiveDataOrigin:  true,
						UserWithAuth:         true,
						AdminWithPolicy:      false,
						NoDA:                 true,
						EncryptedDuplication: false,
						Restricted:           false,
						Decrypt:              true,
						SignEncrypt:          false,
						X509Sign:             false,
					},
					Parameters: tpm2.NewTPMUPublicParms(
						tpm2.TPMAlgECC,
						&tpm2.TPMSECCParms{
							CurveID: tpm2.TPMECCNistP256,
							Scheme: tpm2.TPMTECCScheme{
								Scheme: tpm2.TPMAlgECDH,
								Details: tpm2.NewTPMUAsymScheme(
									tpm2.TPMAlgECDH,
									&tpm2.TPMSKeySchemeECDH{
										HashAlg: tpm2.TPMAlgSHA256,
									},
								),
							},
						},
					),
				}),
			}

			tpmCreateRsp, err := tpmCreate.Execute(thetpm)
			if err != nil {
				t.Fatalf("could not create the TPM key: %v", err)
			}
			keyHandle := tpmutil.Handle(tpmCreateRsp.ObjectHandle)

			outPub, err := tpmCreateRsp.OutPublic.Contents()
			if err != nil {
				t.Fatalf("%v", err)
			}

			pubKey, err := tpmHPKE.Pub(outPub)
			require.NoError(t, err)

			encapKey, ct := encryptFor(t, pubKey, tc.pt, tc.infoSender, tc.infoSeal)

			ecdhZGgenWithTPM := func(keyInfo *tpmHPKE.ECDHZGenKeyInfo, pubPoint tpm2.TPM2BECCPoint) ([]byte, error) {
				return tpmHPKE.ECDHZGen(thetpm, cstpm.NoAuth(), keyInfo, pubPoint)
			}

			receiver := tpmHPKE.NewReceiver(pubKey, tc.infoSender, &tpmHPKE.ECDHZGenKeyInfo{
				PrivKeyHandle: keyHandle,
				PublicName:    tpmCreateRsp.Name,
			}, ecdhZGgenWithTPM)

			opener, err := receiver.Setup(encapKey)
			require.NoError(t, err)

			got, err := opener.Open(ct, tc.infoSeal)
			require.NoError(t, err)

			require.Equal(t, tc.pt, got)
		})
	}
}

func runTPMSimulatorWhile(t *testing.T) transport.TPM {
	thetpm, err := simulator.OpenSimulator()

	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	return thetpm
}

func TestLoadPublicKeyCoordinatePadding(t *testing.T) {
	t.Run("coordinates need padding", func(t *testing.T) {
		tc := []struct {
			name      string
			xBytes    []byte
			numXBytes int
			yBytes    []byte
			numYBytes int
		}{{
			name: "short x coordinate",
			// Valid test case taken from a test flake.
			xBytes:    []byte{7, 44, 33, 109, 186, 227, 9, 60, 50, 66, 201, 93, 189, 135, 182, 13, 19, 217, 250, 183, 16, 80, 67, 105, 96, 110, 9, 175, 159, 233, 201},
			numXBytes: 31,
			yBytes:    []byte{237, 183, 5, 122, 107, 75, 72, 50, 182, 196, 114, 25, 115, 210, 81, 155, 216, 246, 220, 162, 24, 231, 78, 35, 141, 188, 73, 23, 122, 188, 44, 133},
			numYBytes: 32,
		}, {
			name: "short y coordinate",
			// Valid test case taken from a test flake.
			xBytes:    []byte{110, 1, 178, 108, 147, 144, 46, 41, 17, 135, 18, 216, 253, 209, 59, 29, 230, 68, 69, 129, 163, 69, 2, 222, 9, 82, 208, 240, 205, 38, 198, 82},
			numXBytes: 32,
			yBytes:    []byte{54, 99, 240, 28, 171, 217, 122, 60, 120, 117, 144, 93, 165, 42, 87, 197, 151, 78, 168, 59, 5, 151, 59, 156, 74, 62, 139, 117, 38, 142, 28},
			numYBytes: 31,
		}}

		for _, tc := range tc {
			t.Run(tc.name, func(t *testing.T) {
				// Sanity check test setup.
				require.Equal(t, tc.numXBytes, len(tc.xBytes))
				require.Equal(t, tc.numYBytes, len(tc.yBytes))

				tpmt := &tpm2.TPMTPublic{
					Type:    tpm2.TPMAlgECC,
					NameAlg: tpm2.TPMAlgSHA256,
					ObjectAttributes: tpm2.TPMAObject{
						FixedTPM:             true,
						STClear:              false,
						FixedParent:          true,
						SensitiveDataOrigin:  true,
						UserWithAuth:         true,
						AdminWithPolicy:      false,
						NoDA:                 true,
						EncryptedDuplication: false,
						Restricted:           false,
						Decrypt:              true,
						SignEncrypt:          false,
						X509Sign:             false,
					},
					Parameters: tpm2.NewTPMUPublicParms(
						tpm2.TPMAlgECC,
						&tpm2.TPMSECCParms{
							CurveID: tpm2.TPMECCNistP256,
							Scheme: tpm2.TPMTECCScheme{
								Scheme: tpm2.TPMAlgECDH,
								Details: tpm2.NewTPMUAsymScheme(
									tpm2.TPMAlgECDH,
									&tpm2.TPMSKeySchemeECDH{
										HashAlg: tpm2.TPMAlgSHA256,
									},
								),
							},
						},
					),
					Unique: tpm2.NewTPMUPublicID(
						tpm2.TPMAlgECC,
						&tpm2.TPMSECCPoint{
							X: tpm2.TPM2BECCParameter{Buffer: tc.xBytes},
							Y: tpm2.TPM2BECCParameter{Buffer: tc.yBytes},
						},
					),
				}

				// We should still be able to load this public key
				kemPubKey, err := tpmHPKE.Pub(tpmt)
				require.NoError(t, err)
				require.NotNil(t, kemPubKey)
			})
		}
	})
}
