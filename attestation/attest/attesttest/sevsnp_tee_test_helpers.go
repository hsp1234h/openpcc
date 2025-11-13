// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security
//
// Licensed under the Confident Security Limited License, the
// terms and conditions of which are set forth in the "LICENSE"
// file included in the root directory of this code repository
// (the "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at
//
// license.confident.security/limited/v1
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package attesttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	sabi "github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	sevtest "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/uuid"
	cstpm "github.com/openpcc/openpcc/tpm"
	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var SVSMAttestVtpmGUID = uuid.MustParse("c476f1eb-0123-45a5-9641-b4e7dde5bfe3")

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
	internalQuoteProvider *sevtest.QuoteProvider
}

func (*MockQuoteProvider) IsSupported() bool {
	return true
}

func (m *MockQuoteProvider) GetRawQuote(reportData [64]byte) ([]uint8, error) {
	return m.internalQuoteProvider.GetRawQuote(reportData)
}

func (m *MockQuoteProvider) GetRawQuoteSVSM(reportData [64]byte) ([]uint8, error) {
	return m.internalQuoteProvider.GetRawQuote(reportData)
}

func (*MockQuoteProvider) Product() *spb.SevProduct {
	return &spb.SevProduct{
		Name:            spb.SevProduct_SEV_PRODUCT_MILAN,
		MachineStepping: &wrapperspb.UInt32Value{Value: uint32(0)},
	}
}

// SevSnpTestConfig contains configuration options for the test setup
type SevSnpTestConfig struct {
	ArkRevoked           bool // Revoke the ARK certificate
	AskRevoked           bool // Revoke the ASK certificate
	UseMismatchedVcekKey bool // Use a custom VCEK key that doesn't match trusted roots
	UseExtendedReport    bool // Use the extended report format
	UseBadReportData     bool // Use bad report data that doesn't match the hash of the nonce + manifest
	UseMismatchedAK      bool // Use a different AK in the vTPM data in the GUID table
	TPM                  transport.TPMCloser
}

// SevSnpTestSetup encapsulates all the common test setup logic
type SevSnpTestSetup struct {
	Nonce         []byte
	Signer        *sevtest.AmdSigner
	TrustedRoots  map[string][]*trust.AMDRootCerts
	Getter        trust.HTTPSGetter
	QuoteProvider *MockQuoteProvider
}

// setupSevSnpTest creates a common test environment with configurable options
func SetupSevSnpTest(t *testing.T, cfg SevSnpTestConfig) *SevSnpTestSetup {
	t.Helper()
	// Create a random 64 byte nonce
	nonce := make([]byte, 64)
	//nolint: revive
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

	insecureRandomness := rand.Reader

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
	mockQuoteProvider := createMockQuoteProvider(t, cfg, reportSigner, [64]byte(nonce))

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

	return &SevSnpTestSetup{
		Nonce:         nonce,
		Signer:        signer,
		TrustedRoots:  trustedRoots,
		Getter:        getter,
		QuoteProvider: mockQuoteProvider,
	}
}

func createMockQuoteProvider(
	t *testing.T,
	cfg SevSnpTestConfig,
	reportSigner *sevtest.AmdSigner,
	nonce [64]byte,
) *MockQuoteProvider {
	// Create raw report and sign it
	var rawManifest []byte

	reportData := testReportData
	if cfg.UseExtendedReport {
		rawManifest = createRawManifest(t, cfg)
		if cfg.UseBadReportData {
			reportData = [64]byte{0x01}
		} else {
			reportData = sha512.Sum512(append(nonce[:], rawManifest...))
		}
	}

	raw := sevtest.TestRawReportV3(reportData, 0x00a00f10)

	tcs := []sevtest.TestCase{
		{
			Name:     "test",
			Input:    nonce,
			Output:   raw,
			Manifest: rawManifest,
		},
	}

	qpOpts := &sevtest.DeviceOptions{
		Signer: reportSigner,
	}

	internalQP, err := sevtest.TcQuoteProvider(tcs, qpOpts)
	require.NoError(t, err)

	mockQuoteProvider := &MockQuoteProvider{internalQuoteProvider: internalQP}
	return mockQuoteProvider
}

func createRawManifest(t *testing.T, cfg SevSnpTestConfig) []byte {
	tpmtPublic := cstpm.GetRSASSASigningEKTemplate()

	inPublic := tpm2.New2B(tpmtPublic)
	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{},
	}

	handle := tpm2.TPMRHEndorsement
	if cfg.UseMismatchedAK {
		handle = tpm2.TPMRHOwner
	}

	createSigningCommand := tpm2.CreatePrimary{
		PrimaryHandle: handle,
		InPublic:      inPublic,
		CreationPCR:   pcrSelection,
	}
	createSigningResponse, err := createSigningCommand.Execute(cfg.TPM)
	require.NoError(t, err)

	readPublicRequest := tpm2.ReadPublic{
		ObjectHandle: createSigningResponse.ObjectHandle,
	}

	readPublicResponse, err := readPublicRequest.Execute(cfg.TPM)
	require.NoError(t, err)

	outPub, err := readPublicResponse.OutPublic.Contents()
	require.NoError(t, err)

	manifest := sabi.ServicesManifest{
		Entries: []sabi.ServiceEntry{
			{
				GUID: SVSMAttestVtpmGUID,
				Data: tpm2.Marshal(outPub),
			},
		},
	}

	rawManifest, err := manifest.Marshal()
	require.NoError(t, err)

	return rawManifest
}
