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
	"encoding/pem"
	"errors"
	"testing"

	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/stretchr/testify/require"
)

func TestAttestGceAkIntermediateCertificate(t *testing.T) {
	testFS := test.TextArchiveFS(t, "testdata/gce_ak_certificates.txt")
	testAKCert := test.ReadFile(t, testFS, "test_gce_ak_cert.pem")

	t.Run("success", func(t *testing.T) {
		selfSigned, err := generateSelfSignedCert()
		require.NoError(t, err)

		block, _ := pem.Decode(testAKCert)
		require.NotNilf(t, block, "could not decode test certificate: PEM block is nil")

		cert, err := x509.ParseCertificate(block.Bytes)

		require.NoErrorf(t, err, "could not parse test certificate: %v", err)

		intermediateCertUrl := cert.IssuingCertificateURL[0]

		attestor := attest.NewGceAkIntermediateCertificateAttestorWithGetter(
			*cert,
			func(url string) (*x509.Certificate, error) {
				if url == intermediateCertUrl {
					return selfSigned, nil
				}
				return nil, errors.New("not found: " + url)
			},
		)

		se, err := attestor.CreateSignedEvidence(t.Context())

		require.NoError(t, err)
		require.Equal(t, se.Signature, selfSigned.Signature)
	})

	t.Run("failure, bad root certificate", func(t *testing.T) {
		badCert, err := generateSelfSignedCert()

		require.NoError(t, err)

		se := &evidence.SignedEvidencePiece{
			Type:      evidence.GceAkIntermediateCertificate,
			Data:      badCert.Raw,
			Signature: badCert.Signature,
		}

		verifiedCert, err := verify.GceAkIntermediateCertificate(se)

		require.ErrorContains(t, err, "certificate did not chain to a trusted root")
		require.Nil(t, verifiedCert)
	})
}
