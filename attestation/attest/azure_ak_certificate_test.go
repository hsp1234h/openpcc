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
	"encoding/pem"
	"testing"

	_ "embed"

	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/verify"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/stretchr/testify/require"
)

func Test_VerifyAzureSEVSNPCertificate_Success(t *testing.T) {
	testCases := []struct {
		name     string
		testFile string
	}{
		{
			// NB: This cert is slated to expire in fall of 2026.
			// When that happens, we will need to regenerate it / pull a new one from an Azure machine.
			name:     "certificate_01",
			testFile: "test_azure_ak_certificate_01.pem",
		},
		{
			// NB: This cert is slated to expire in summer of 2026.
			// When that happens, we will need to regenerate it / pull a new one from an Azure machine.
			name:     "certificate_03",
			testFile: "test_azure_ak_certificate_03.pem",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testFS := test.TextArchiveFS(t, "testdata/azure_ak_certificates.txt")
			testAzureAKCertificatePEM := test.ReadFile(t, testFS, tc.testFile)

			tpmSimulator, err := simulator.OpenSimulator()
			if err != nil {
				t.Fatalf("could not connect to TPM simulator: %v", err)
			}

			t.Cleanup(func() {
				if err := tpmSimulator.Close(); err != nil {
					t.Errorf("%v", err)
				}
			})

			// Parse the certificate
			block, _ := pem.Decode(testAzureAKCertificatePEM)
			if block == nil {
				t.Fatal("failed to parse PEM block containing public key")
				return
			}

			mockTpm := &TPMNVWrapper{
				realtpm:       tpmSimulator,
				responseBytes: block.Bytes,
			}

			attestor := attest.NewAzureAkCertificateAttestor(mockTpm)
			se, err := attestor.CreateSignedEvidence(t.Context())
			require.NoError(t, err)
			require.NotNil(t, se)

			verifiedCert, err := verify.AzureAkCertificate(se)
			require.NoError(t, err)
			require.NotNil(t, verifiedCert)
		})
	}
}

func Test_VerifyAzureSEVSNPCertificate_FailureBadCert(t *testing.T) {
	cert, err := generateSelfSignedCert()

	if err != nil {
		t.Fatalf("could not generate self-signed certificate: %v", err)
	}
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	mocktpm := &TPMNVWrapper{
		realtpm:       thetpm,
		responseBytes: cert.Raw,
	}

	attestor := attest.NewAzureAkCertificateAttestor(mocktpm)
	se, err := attestor.CreateSignedEvidence(t.Context())
	require.NoError(t, err)
	require.NotNil(t, se)

	verifiedCert, err := verify.AzureAkCertificate(se)
	require.ErrorContains(t, err, "certificate did not chain to a trusted root")
	require.Nil(t, verifiedCert)

}
