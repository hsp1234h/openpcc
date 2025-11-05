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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestPub(t *testing.T) {

	t.Parallel()

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := map[string]struct {
		public *tpm2.TPMTPublic
		result bool
	}{
		"valid rsa": {
			public: &tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgRSA,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:             true,
					STClear:              false,
					FixedParent:          true,
					SensitiveDataOrigin:  true,
					UserWithAuth:         true,
					AdminWithPolicy:      false,
					NoDA:                 false,
					EncryptedDuplication: false,
					Restricted:           true,
					Decrypt:              true,
					SignEncrypt:          false,
				},
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits:  tpm2.TPMKeyBits(rsaKey.N.BitLen()),
						Exponent: 0,
						Symmetric: tpm2.TPMTSymDefObject{
							Algorithm: tpm2.TPMAlgAES,
							Mode: tpm2.NewTPMUSymMode(
								tpm2.TPMAlgAES,
								tpm2.TPMAlgCFB,
							),
							KeyBits: tpm2.NewTPMUSymKeyBits(
								tpm2.TPMAlgAES,
								tpm2.TPMKeyBits(128),
							),
						},
					},
				),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgRSA,
					&tpm2.TPM2BPublicKeyRSA{
						Buffer: rsaKey.N.Bytes(),
					},
				),
			},
			result: true,
		},
		"valid ecdsa": {
			public: &tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgECC,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM:             true,
					STClear:              false,
					FixedParent:          true,
					SensitiveDataOrigin:  true,
					UserWithAuth:         true,
					AdminWithPolicy:      false,
					NoDA:                 false,
					EncryptedDuplication: false,
					Restricted:           true,
					Decrypt:              true,
					SignEncrypt:          false,
				},
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP256,
						Scheme: tpm2.TPMTECCScheme{
							Scheme: tpm2.TPMAlgECDSA,
							Details: tpm2.NewTPMUAsymScheme(
								tpm2.TPMAlgECDSA,
								&tpm2.TPMSSigSchemeECDSA{
									HashAlg: tpm2.TPMAlgSHA256,
								},
							),
						},
					},
				),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCPoint{
						X: tpm2.TPM2BECCParameter{
							Buffer: ecdsaKey.X.Bytes(),
						},
						Y: tpm2.TPM2BECCParameter{
							Buffer: ecdsaKey.Y.Bytes(),
						},
					},
				),
			},
			result: true,
		},
		"unsupported algorithm": {
			public: &tpm2.TPMTPublic{
				Type: tpm2.TPMAlgAES,
			},
			result: false,
		},
	}

	for name, test := range tests {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key, err := Pub(test.public)

			if (key != nil) != test.result {
				t.Errorf("Not equal: \n"+
					"expected: %v\n"+
					"actual  : %v",
					test.result,
					key != nil,
				)
			}

			if (err == nil) != test.result {
				t.Errorf("Not equal: \n"+
					"expected: %v\n"+
					"actual  : %v",
					test.result,
					err == nil,
				)
			}

			if key != nil {
				switch key := key.(type) {
				case *rsa.PublicKey:
					if !reflect.DeepEqual(rsaKey.PublicKey, *key) {
						t.Errorf("Not equal: \n"+
							"expected: %v\n"+
							"actual  : %v",
							rsaKey.PublicKey,
							key,
						)
					}
				case *ecdsa.PublicKey:
					if !reflect.DeepEqual(ecdsaKey.PublicKey, *key) {
						t.Errorf("Not equal: \n"+
							"expected: %v\n"+
							"actual  : %v",
							ecdsaKey.PublicKey,
							key,
						)
					}
				default:
					t.Fatalf("unexpected case")
				}
			}
		})
	}
}
