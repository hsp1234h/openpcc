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
	//go:embed azure_tpm_intermediate_01.pem
	azureTPMIntermediateCertPEM01 []byte
	//go:embed azure_tpm_intermediate_03.pem
	azureTPMIntermediateCertPEM03 []byte

	azureTPMIntermediateCertPEMs = [][]byte{azureTPMIntermediateCertPEM01, azureTPMIntermediateCertPEM03}

	//go:embed azure_tpm_root_2023.pem
	azureTPMRootCertPEM []byte
)

func AzureAkCertificate(
	signedEvidencePiece *ev.SignedEvidencePiece,
) (*x509.Certificate, error) {
	// Parse the intermediate certificates
	var intermediateCerts = make([]*x509.Certificate, 0, len(azureTPMIntermediateCertPEMs))
	for i, certPEM := range azureTPMIntermediateCertPEMs {
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, fmt.Errorf("failed to parse PEM block containing intermediate cert (index %d)", i)
		}

		intermediateCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse intermediate cert (index %d)", i)
		}

		intermediateCerts = append(intermediateCerts, intermediateCert)
	}

	// Parse the root certificate
	block, _ := pem.Decode(azureTPMRootCertPEM)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing root cert")
	}

	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse root cert")
	}

	akCert, err := x509.ParseCertificate(signedEvidencePiece.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Azure AK Certificate from evidence: %w", err)
	}

	rootCerts := []*x509.Certificate{rootCert}

	err = VerifyAKCert(
		akCert,
		rootCerts,
		intermediateCerts,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to verify Azure AK Certificate: %w", err)
	}

	return akCert, nil
}
