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
package verify

import (
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/verify"
	"github.com/openpcc/openpcc/attestation/evidence"

	"github.com/google/go-tdx-guest/proto/checkconfig"
)

var (
	//go:embed tdx_root.pem
	TDXRootCertBytes []byte
)

func certificateToPEMString(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	// Create a PEM block with the certificate data
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	// Encode to PEM format and return as string
	pemBytes := pem.EncodeToMemory(block)
	if pemBytes == nil {
		return ""
	}

	return string(pemBytes)
}

type HardcodedCollateralGetter struct {
	Collateral evidence.TDXCollateral
}

func (g *HardcodedCollateralGetter) Get(reqURL string) (map[string][]string, []byte, error) {
	parsedURL, err := url.Parse(reqURL)
	if err != nil {
		return nil, nil, err
	}

	switch parsedURL.Path {
	case "/sgx/certification/v4/pckcrl":
		return g.Collateral.PckCrlHeaders, g.Collateral.PckCrlBody, nil
	case "/tdx/certification/v4/tcb":
		return g.Collateral.TcbHeaders, g.Collateral.TcbBody, nil
	case "/tdx/certification/v4/qe/identity":
		return g.Collateral.QeHeaders, g.Collateral.QeBody, nil
	case "/IntelSGXRootCA.der":
		return g.Collateral.RootCrlHeaders, g.Collateral.RootCrlBody, nil
	default:
		return nil, nil, errors.New("no hardcode response for request")
	}
}

func TDXReport(
	_ context.Context,
	rootCert *x509.Certificate,
	collateral evidence.TDXCollateral,
	signedEvidencePiece *evidence.SignedEvidencePiece,
) error {
	report, err := abi.QuoteToProto(signedEvidencePiece.Data)

	if err != nil {
		return fmt.Errorf("failed to convert quote to proto: %w", err)
	}

	rootOfTrust := &checkconfig.RootOfTrust{}

	rootOfTrust.GetCollateral = true
	rootOfTrust.CheckCrl = true
	rootOfTrust.Cabundles = []string{
		certificateToPEMString(rootCert),
	}

	options, err := verify.RootOfTrustToOptions(rootOfTrust)
	options.GetCollateral = true
	options.CheckRevocations = true
	options.Getter = &HardcodedCollateralGetter{
		Collateral: collateral,
	}

	if err != nil {
		return fmt.Errorf("failed to convert root of trust to options: %w", err)
	}
	err = verify.TdxQuote(report, options)

	if err != nil {
		return fmt.Errorf("failed to verify TDX quote: %w", err)
	}

	return nil
}

func GetTDXRootCert() (*x509.Certificate, error) {
	// Parse the default root certificate
	block, _ := pem.Decode(TDXRootCertBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
