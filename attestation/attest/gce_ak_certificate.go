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
	_ "embed" // Necessary to use go:embed
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/openpcc/openpcc/attestation/evidence"
	cstpm "github.com/openpcc/openpcc/tpm"
)

// GCE Attestation Key NV Indices
// Sources for these constants:
// https://github.com/google/go-tpm/blob/364d5f2f78b95ba23e321373466a4d881181b85d/legacy/tpm2/tpm2.go#L1429
// github.com/google/go-tpm-tools@v0.4.4/client/handles.go
// [go-tpm-tools/client](https://pkg.go.dev/github.com/google/go-tpm-tools/client#pkg-constants)
const (
	// RSA 2048 AK.
	GceAKCertNVIndexRSA uint32 = 0x01c10000
	// ECC P256 AK.
	GceAKCertNVIndexECC uint32 = 0x01c10002
)

type GceAkCertificateAttestor struct {
	tpm transport.TPM
}

func NewGceAkCertificateAttestor(tpm transport.TPM) *GceAkCertificateAttestor {
	return &GceAkCertificateAttestor{
		tpm: tpm,
	}
}

func (*GceAkCertificateAttestor) Name() string {
	return "GceAkCertificateAttestor"
}

func (a *GceAkCertificateAttestor) CreateSignedEvidence(_ context.Context) (*evidence.SignedEvidencePiece, error) {
	certData, err := cstpm.NVReadEXNoAuthorization(a.tpm, tpmutil.Handle(GceAKCertNVIndexRSA))

	if err != nil {
		return nil, err
	}

	// Try parsing certData as DER encoded x509 certificate
	cert, err := x509.ParseCertificate(certData)

	if err != nil {
		return nil, fmt.Errorf("failed to parse Certificate: %w", err)
	}

	return &evidence.SignedEvidencePiece{
		Type:      evidence.GceAkCertificate,
		Data:      certData,
		Signature: cert.Signature,
	}, nil
}
