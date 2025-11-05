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
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify/trust"
	"github.com/stretchr/testify/require"

	"github.com/openpcc/openpcc/attestation/attest"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"
	test "github.com/openpcc/openpcc/inttest"
)

func Test_VerifyTDXReport_Success(t *testing.T) {
	testFS := test.TextArchiveFS(t, "testdata/gce_tdx_report.txt")
	testGceTDXReportPEM := test.ReadFile(t, testFS, "test_gce_tdx_report.pem")
	quote, err := abi.QuoteToProto(pemReportToBytes(testGceTDXReportPEM))

	require.NoError(t, err)

	quoteV4, ok := quote.(*pb.QuoteV4)

	require.True(t, ok)

	chain, err := attest.ExtractChainFromQuoteV4(quoteV4)
	require.NoError(t, err)

	collateralAttestor, err := attest.NewTDXCollateralAttestor(
		&trust.SimpleHTTPSGetter{},
		chain.PCKCertificate,
	)
	require.NoError(t, err)

	collateralEvidencePiece, err := collateralAttestor.CreateSignedEvidence(t.Context())

	require.NoError(t, err)

	tdxCollateral := &ev.TDXCollateral{}

	tdxCollateral.UnmarshalBinary(collateralEvidencePiece.Data)

	t.Run("success", func(t *testing.T) {
		root, err := verify.GetTDXRootCert()

		require.NoError(t, err)

		evidencePiece := &ev.SignedEvidencePiece{
			Type:      ev.TdxReport,
			Data:      pemReportToBytes(testGceTDXReportPEM),
			Signature: make([]byte, 64),
		}

		err = verify.TDXReport(t.Context(), root, *tdxCollateral, evidencePiece)
		require.NoError(t, err)
	})

	t.Run("failure, bad root certificate", func(t *testing.T) {
		root, err := generateSelfSignedCert()

		require.NoError(t, err)

		evidencePiece := &ev.SignedEvidencePiece{
			Type:      ev.TdxReport,
			Data:      pemReportToBytes(testGceTDXReportPEM),
			Signature: make([]byte, 64),
		}
		err = verify.TDXReport(t.Context(), root, *tdxCollateral, evidencePiece)
		require.ErrorContains(t, err, "certificate signed by unknown authority")
	})

	t.Run("failure, report tampered", func(t *testing.T) {
		root, err := verify.GetTDXRootCert()

		require.NoError(t, err)

		reportBytes := pemReportToBytes(testGceTDXReportPEM)

		quote, err := abi.QuoteToProto(reportBytes)

		require.NoError(t, err)

		quoteV4 := quote.(*pb.QuoteV4)

		// alter the run time measurement register
		_, err = rand.Read(quoteV4.TdQuoteBody.Rtmrs[1])
		require.NoError(t, err)

		tamperedBytes, err := abi.QuoteToAbiBytes(quoteV4)

		require.NoError(t, err)

		evidencePiece := &ev.SignedEvidencePiece{
			Type:      ev.TdxReport,
			Data:      tamperedBytes,
			Signature: make([]byte, 64),
		}

		chain, err := attest.ExtractChainFromQuoteV4(quoteV4)
		require.NoError(t, err)

		collateralAttestor, err := attest.NewTDXCollateralAttestor(
			&trust.SimpleHTTPSGetter{},
			chain.PCKCertificate,
		)
		require.NoError(t, err)

		collaeralSe, err := collateralAttestor.CreateSignedEvidence(t.Context())

		require.NoError(t, err)

		collateral := ev.TDXCollateral{}

		collateral.UnmarshalBinary(collaeralSe.Data)

		err = verify.TDXReport(t.Context(), root, collateral, evidencePiece)
		require.ErrorContains(t, err, "unable to verify message digest using quote's signature and ecdsa attestation key")
	})

	t.Run("failure, report corrupted", func(t *testing.T) {
		root, err := verify.GetTDXRootCert()

		require.NoError(t, err)

		reportBytes := pemReportToBytes(testGceTDXReportPEM)

		reportBytes[0] = 0x0A

		evidencePiece := &ev.SignedEvidencePiece{
			Type:      ev.TdxReport,
			Data:      reportBytes,
			Signature: make([]byte, 64),
		}

		err = verify.TDXReport(t.Context(), root, *tdxCollateral, evidencePiece)
		require.ErrorContains(t, err, "quote format not supported")
	})

}

func pemReportToBytes(data []byte) []byte {
	block, _ := pem.Decode(data)
	return block.Bytes
}

func generateSelfSignedCert() (*x509.Certificate, error) {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Define certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	// Create the self-signed certificate
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template, // self-signed, so subject and issuer are the same
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil

}
