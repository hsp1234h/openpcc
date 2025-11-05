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

package attest

import (
	"context"

	"crypto/x509"
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/openpcc/openpcc/attestation/evidence"
	cstpm "github.com/openpcc/openpcc/tpm"
)

// This index isnt really documented anywhere, but it is used in the Signal project
// https://github.com/signalapp/SecureValueRecovery2/blob/9d5df31e6a6616f1d91d953e89f219cf1b211b34/enclave/env/azuresnp/azuresnp.cc#L109
const (
	// RSA 2048 AK.
	AzureAKCertNVIndexRSA uint32 = 0x1C101D0
)

type AzureAkCertificateAttestor struct {
	tpm transport.TPM
}

func NewAzureAkCertificateAttestor(tpm transport.TPM) *AzureAkCertificateAttestor {
	return &AzureAkCertificateAttestor{
		tpm: tpm,
	}
}

func (*AzureAkCertificateAttestor) Name() string {
	return "AzureAkCertificateAttestor"
}

func (a *AzureAkCertificateAttestor) CreateSignedEvidence(_ context.Context) (*evidence.SignedEvidencePiece, error) {
	certData, err := cstpm.NVReadEXNoAuthorization(a.tpm, tpmutil.Handle(AzureAKCertNVIndexRSA))

	if err != nil {
		return nil, err
	}

	// Try parsing certData as DER encoded x509 certificate
	cert, err := ParseAzureAKCertificate(certData)

	if err != nil {
		return nil, fmt.Errorf("failed to parse azure certificate from nv ram: %w", err)
	}

	return &evidence.SignedEvidencePiece{
		Type:      evidence.AzureAkCertificate,
		Data:      cert.Raw,
		Signature: cert.Signature,
	}, nil
}

/* The certificate we read from NVRam has trailing zero bytes. OpenSSL parses it without
 * any issues, but the Go parser does not. So we need to trim the trailing zero bytes.
 * This is a bit of a hack, as x509 certificates are variable length, but
 * should be safe and relatively efficient. */
func ParseAzureAKCertificate(tpmDerBytes []byte) (*x509.Certificate, error) {
	rawLength := len(tpmDerBytes)

	certificate, err := x509.ParseCertificate(tpmDerBytes)
	if err == nil {
		return certificate, nil
	}

	// Try trimming all 0 bytes from the end
	for end := rawLength; end > 800; end-- {
		certificate, err := x509.ParseCertificate(tpmDerBytes[:end])

		if err == nil {
			return certificate, nil
		}
	}

	return nil, fmt.Errorf("could not parse azure AK certificate: %w", err)
}
