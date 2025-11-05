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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/pem"
	"math/big"
	insecurerand "math/rand"
	"strings"
	"testing"
	"time"

	sabi "github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	sevtest "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"
)

var (
	testReportData = [64]byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0}
)

type MockQuoteProvider struct {
	Quote []byte
}

func (m *MockQuoteProvider) IsSupported() bool {
	return true
}

func (m *MockQuoteProvider) GetRawQuote(reportData [64]byte) ([]uint8, error) {
	return m.Quote, nil
}

func (m *MockQuoteProvider) Product() *spb.SevProduct {
	return &spb.SevProduct{
		Name:            spb.SevProduct_SEV_PRODUCT_MILAN,
		MachineStepping: &wrapperspb.UInt32Value{Value: uint32(0)},
	}
}

// sevSnpTestConfig contains configuration options for the test setup
type sevSnpTestConfig struct {
	ArkRevoked           bool // Revoke the ARK certificate
	AskRevoked           bool // Revoke the ASK certificate
	UseMismatchedVcekKey bool // Use a custom VCEK key that doesn't match trusted roots
}

// sevSnpTestSetup encapsulates all the common test setup logic
type sevSnpTestSetup struct {
	Nonce         []byte
	Signer        *sevtest.AmdSigner
	TrustedRoots  map[string][]*trust.AMDRootCerts
	Getter        trust.HTTPSGetter
	QuoteProvider *MockQuoteProvider
	Attestor      *attest.SEVSNPTEEAttestor
	Evidence      evidence.SignedEvidencePiece
}

// setupSevSnpTest creates a common test environment with configurable options
func setupSevSnpTest(t *testing.T, cfg sevSnpTestConfig) *sevSnpTestSetup {
	// Create a random 64 byte nonce
	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	// Create the primary signer for trusted roots
	signer, err := sevtest.DefaultTestOnlyCertChain(sevtest.GetProductName(), time.Now())
	require.NoError(t, err)

	// Setup for the report signing (may be different from trusted roots)
	var reportSigner = signer
	var customVcekKey *ecdsa.PrivateKey

	// Generate a random VCEK key if requested
	if cfg.UseMismatchedVcekKey {
		customVcekKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		now := time.Now()
		sb := &sevtest.AmdSignerBuilder{
			ProductName:      sevtest.GetProductName(),
			ArkCreationTime:  now,
			AskCreationTime:  now,
			VcekCreationTime: now,
			CSPID:            "go-sev-guest",
			Keys: &sevtest.AmdKeys{
				Ark:  signer.Keys.Ark,
				Ask:  signer.Keys.Ask,
				Asvk: signer.Keys.Asvk,
				Vcek: customVcekKey,
				Vlek: signer.Keys.Vlek,
			},
			VcekCustom: sevtest.CertOverride{
				SerialNumber: big.NewInt(0xd),
			},
			AskCustom: sevtest.CertOverride{
				SerialNumber: big.NewInt(0x8088),
			},
		}
		reportSigner, err = sb.TestOnlyCertChain()
		require.NoError(t, err)
	}

	// Create list of revoked certificates based on config
	var revokedCerts []pkix.RevokedCertificate

	if cfg.ArkRevoked {
		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
			SerialNumber:   signer.Ark.SerialNumber,
			RevocationTime: time.UnixMilli(0),
		})
	}

	if cfg.AskRevoked {
		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
			SerialNumber:   signer.Ask.SerialNumber,
			RevocationTime: time.UnixMilli(0),
		})
	}

	insecureRandomness := insecurerand.New(insecurerand.NewSource(0xc0de))

	// Create CRL
	template := &x509.RevocationList{
		SignatureAlgorithm:  x509.SHA384WithRSAPSS,
		RevokedCertificates: revokedCerts,
		Number:              big.NewInt(1),
	}

	crl, err := x509.CreateRevocationList(insecureRandomness, template, signer.Ark, signer.Keys.Ark)
	require.NoError(t, err)

	// Build cert chain
	b := &strings.Builder{}
	err = multierr.Combine(
		pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Ask.Raw}),
		pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Ark.Raw}),
	)
	require.NoError(t, err)

	// Create getter with certs
	getter := sevtest.SimpleGetter(map[string][]byte{
		"https://kdsintf.amd.com/vcek/v1/Milan/00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000?blSPL=0&teeSPL=0&snpSPL=0&ucodeSPL=0": signer.Vcek.Raw,
		"https://kdsintf.amd.com/vcek/v1/Milan/cert_chain": []byte(b.String()),
		"https://kdsintf.amd.com/vcek/v1/Milan/crl":        crl,
	})

	// Create raw report and sign it
	raw := sevtest.TestRawReportV3(testReportData, 0x00a00f10)
	report := raw[:sabi.ReportSize]
	r, s, err := reportSigner.Sign(sabi.SignedComponent(report))
	require.NoError(t, err)
	sabi.SetSignature(r, s, report)
	copy(raw[:], report)

	mockQuoteProvider := &MockQuoteProvider{Quote: raw[:]}

	attestor := &attest.SEVSNPTEEAttestor{
		Nonce:         nonce,
		QuoteProvider: mockQuoteProvider,
		Getter:        getter,
	}

	evidence, err := attestor.CreateSignedEvidence(t.Context())
	require.NoError(t, err)

	trustedRoots := map[string][]*trust.AMDRootCerts{
		sevtest.GetProductLine(): {func() *trust.AMDRootCerts {
			r := trust.AMDRootCertsProduct(sevtest.GetProductLine())
			r.ProductCerts = &trust.ProductCerts{
				Ark: signer.Ark,
				Ask: signer.Ask,
			}
			return r
		}()},
	}

	return &sevSnpTestSetup{
		Nonce:         nonce,
		Signer:        signer,
		TrustedRoots:  trustedRoots,
		Getter:        getter,
		QuoteProvider: mockQuoteProvider,
		Attestor:      attestor,
		Evidence:      *evidence,
	}
}

func Test_VerifySEVSNPReport_Success(t *testing.T) {
	// Happy path with no revoked certs or key mismatches
	setup := setupSevSnpTest(t, sevSnpTestConfig{})

	err := verify.SEVSNPReport(t.Context(), &setup.Evidence, true, setup.Getter)
	require.NoError(t, err)
}

func Test_VerifySEVSNPReport_FailureArkRevoked(t *testing.T) {
	// Test with ARK certificate revoked
	setup := setupSevSnpTest(t, sevSnpTestConfig{ArkRevoked: true})

	err := verify.SEVSNPReport(t.Context(), &setup.Evidence, true, setup.Getter)
	require.Error(t, err, "should fail when ARK is revoked")
}

func Test_VerifySEVSNPReport_FailureAskRevoked(t *testing.T) {
	// Test with ASK certificate revoked
	setup := setupSevSnpTest(t, sevSnpTestConfig{AskRevoked: true})

	err := verify.SEVSNPReport(t.Context(), &setup.Evidence, true, setup.Getter)
	require.Error(t, err, "should fail when ASK is revoked")
}

func Test_VerifySEVSNPReport_FailureSignerRootMismatch(t *testing.T) {
	// Test with a mismatched VCEK key
	setup := setupSevSnpTest(t, sevSnpTestConfig{UseMismatchedVcekKey: true})

	err := verify.SEVSNPReport(t.Context(), &setup.Evidence, true, setup.Getter)
	require.Error(t, err, "should fail with signer root mismatch")
}
