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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/openpcc/openpcc/attestation/evidence"
)

type GceAkIntermediateCertificateAttestor struct {
	tpmCert           x509.Certificate
	certificateGetter (func(string) (*x509.Certificate, error))
}

func NewGceAkIntermediateCertificateAttestor(tpmCert x509.Certificate) *GceAkIntermediateCertificateAttestor {
	return &GceAkIntermediateCertificateAttestor{
		tpmCert:           tpmCert,
		certificateGetter: CheckDomainAndSchemeGetter,
	}
}

func NewGceAkIntermediateCertificateAttestorWithGetter(tpmCert x509.Certificate, getter func(string) (*x509.Certificate, error)) *GceAkIntermediateCertificateAttestor {
	return &GceAkIntermediateCertificateAttestor{
		tpmCert:           tpmCert,
		certificateGetter: getter,
	}
}

func (*GceAkIntermediateCertificateAttestor) Name() string {
	return "GceAkIntermediateCertificateAttestor"
}

func (a *GceAkIntermediateCertificateAttestor) CreateSignedEvidence(_ context.Context) (*evidence.SignedEvidencePiece, error) {
	intermediateCertURLs := a.tpmCert.IssuingCertificateURL
	intermediateCerts := make([]*x509.Certificate, 0, len(intermediateCertURLs))

	for _, intermediateCertURL := range intermediateCertURLs {
		intermediateCert, err := a.certificateGetter(intermediateCertURL)
		if err != nil {
			return nil, fmt.Errorf("failed to get intermediate cert: %w", err)
		}

		intermediateCerts = append(intermediateCerts, intermediateCert)
	}

	// Fail if more than one intermediate cert is found
	if len(intermediateCerts) != 1 {
		return nil, errors.New("multiple intermediate certs found")
	}
	intermediateCert := intermediateCerts[0]

	return &evidence.SignedEvidencePiece{
		Type:      evidence.GceAkIntermediateCertificate,
		Data:      intermediateCert.Raw,
		Signature: intermediateCert.Signature,
	}, nil
}

func CheckDomainAndSchemeGetter(urlUnverified string) (*x509.Certificate, error) {
	slog.Info("Downloading certificate from", "url", urlUnverified)

	// Before making the HTTP request
	parsedURL, err := url.Parse(urlUnverified)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	allowedDomain := "storage.googleapis.com"
	if !strings.HasSuffix(parsedURL.Host, allowedDomain) && parsedURL.Host != allowedDomain {
		return nil, errors.New("URL host must be storage.googleapis.com or its subdomain")
	}

	// ensure we're using encryption
	if parsedURL.Scheme != "https" {
		slog.Warn("DownloadCert via an unexpected scheme, changed to https", "url", urlUnverified, "scheme", parsedURL.Scheme)
		parsedURL.Scheme = "https"
	}

	// Download the intermediate certificate
	resp, err := http.Get(parsedURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to download certificate: %w", err)
	}
	defer resp.Body.Close()

	// Read the certificate data
	certData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certData)

	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
