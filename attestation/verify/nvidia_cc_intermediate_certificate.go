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
	"encoding/pem"
	"errors"
	"fmt"

	ev "github.com/openpcc/openpcc/attestation/evidence"
)

func GetIntermediateCert(signedEvidencePiece *ev.SignedEvidencePiece) (*x509.Certificate, error) {
	intermediateCert, err := x509.ParseCertificate(signedEvidencePiece.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse intermediate certificate: %w", err)
	}
	block, _ := pem.Decode(NRASRootCert)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the root certificate")
	}
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root certificate: %w", err)
	}

	rootCerts := []*x509.Certificate{rootCert}

	err = verifyIntermediateCert(
		intermediateCert,
		rootCerts,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to verify Nvidia Intermediate Certificate: %w", err)
	}

	return intermediateCert, nil
}
