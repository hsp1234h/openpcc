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
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"testing"

	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"
	test "github.com/openpcc/openpcc/inttest"

	"github.com/stretchr/testify/require"
)

func TestVerifyGceAkCertificate(t *testing.T) {
	testFS := test.TextArchiveFS(t, "testdata/gce_ak_certificates.txt")
	testAKCert := test.ReadFile(t, testFS, "test_gce_ak_cert.pem")
	testIntermediateAKCert := test.ReadFile(t, testFS, "test_gce_ak_intermediate_cert.pem")

	t.Run("success", func(t *testing.T) {
		block, _ := pem.Decode(testIntermediateAKCert)
		require.NotNil(t, block, "could not decode test certificate: PEM block is nil")

		intermediateCert, err := x509.ParseCertificate(block.Bytes)
		require.NoErrorf(t, err, "could not parse test certificate: %v", err)

		block, _ = pem.Decode(testAKCert)

		//nolint:staticcheck // SA5011 the Fatalf should prevent this null deref
		if block == nil {
			t.Fatalf("could not decode test certificate: PEM block is nil")
		}

		//nolint:staticcheck // SA5011 the Fatalf should prevent this null deref
		akCert, err := x509.ParseCertificate(block.Bytes)

		require.NoErrorf(t, err, "could not parse test certificate: %v", err)

		se := &evidence.SignedEvidencePiece{
			Type:      evidence.GceAkCertificate,
			Data:      akCert.Raw,
			Signature: akCert.Signature,
		}

		verifiedAkCert, info, err := verify.GceAkCertificate(*intermediateCert, se)

		require.NoError(t, err)

		require.NotNil(t, info)
		require.NotNil(t, verifiedAkCert)
		require.Equal(t, "jfquinn-tdx-tpm-ubuntu-test-us-west1-b", info.InstanceName)
		require.Equal(t, "us-west1-b", info.Zone)
	})

	t.Run("failure, bad intermediate cert", func(t *testing.T) {
		block, _ := pem.Decode(testAKCert)
		require.NotNil(t, block, "could not decode test certificate: PEM block is nil")

		akCert, err := x509.ParseCertificate(block.Bytes)

		require.NoErrorf(t, err, "could not parse test certificate: %v", err)

		intermediateCert, err := generateSelfSignedCert()

		require.NoError(t, err)

		se := &evidence.SignedEvidencePiece{
			Type:      evidence.GceAkCertificate,
			Data:      akCert.Raw,
			Signature: akCert.Signature,
		}

		cert, info, err := verify.GceAkCertificate(*intermediateCert, se)

		require.ErrorContains(t, err, "certificate did not chain to a trusted root")
		require.Nil(t, cert)
		require.Nil(t, info)
	})
}
