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
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"

	ev "github.com/openpcc/openpcc/attestation/evidence"
)

var (
	//go:embed gce_ek_ak_root.pem
	GCEEKAKRootCert []byte
)

func GetGCEEKAKRootCert() (*x509.Certificate, error) {
	// Parse the default root certificate
	block, _ := pem.Decode(GCEEKAKRootCert)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// VerifIntermediateAKCert checks a given Attestation Key intermediate certificate against
// the provided google root CA
func verifyIntermediateCert(akIntermediateCert *x509.Certificate, trustedRootCerts []*x509.Certificate) error {
	if akIntermediateCert == nil {
		return errors.New("failed to validate AK Cert: received nil cert")
	}
	if len(trustedRootCerts) == 0 {
		return errors.New("failed to validate AK Cert: received no trusted root certs")
	}

	x509Opts := x509.VerifyOptions{
		Roots: makePool(trustedRootCerts),
		// The default key usage (ExtKeyUsageServerAuth) is not appropriate for
		// an Attestation Key: ExtKeyUsage of
		// - https://oidref.com/2.23.133.8.1
		// - https://oidref.com/2.23.133.8.3
		// https://pkg.go.dev/crypto/x509#VerifyOptions
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := akIntermediateCert.Verify(x509Opts); err != nil {
		return fmt.Errorf("certificate did not chain to a trusted root: %w", err)
	}

	return nil
}

func GceAkIntermediateCertificate(
	signedEvidencePiece *ev.SignedEvidencePiece,
) (*x509.Certificate, error) {
	akIntermediateCert, err := x509.ParseCertificate(signedEvidencePiece.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GCE AK Certificate: %w", err)
	}

	rootCert, err := GetGCEEKAKRootCert()
	if err != nil {
		return nil, fmt.Errorf("failed to get GCE EK AK Root Certificate: %w", err)
	}

	rootCerts := []*x509.Certificate{rootCert}

	err = verifyIntermediateCert(
		akIntermediateCert,
		rootCerts,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to verify GCE AK Certificate: %w", err)
	}

	return akIntermediateCert, nil
}
