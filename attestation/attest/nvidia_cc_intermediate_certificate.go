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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	ev "github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/otel/otelutil"
)

const (
	nvidiaJWKSURL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"
)

type NvidiaCCIntermediateCertificateAttestor struct {
	certProvider CertificateProvider
	JWTToken     string
	EvidenceType ev.EvidenceType
}

type CertificateProvider interface {
	GetCertificate(ctx context.Context, jwtToken string) (*x509.Certificate, error)
}

func NewNvidiaCCIntermediateCertificateAttestor(jwtToken string, evidenceType ev.EvidenceType) *NvidiaCCIntermediateCertificateAttestor {
	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: otelutil.NewTransport(http.DefaultTransport),
	}
	return &NvidiaCCIntermediateCertificateAttestor{
		certProvider: &NRASCertificateProvider{
			NRASURL:    nvidiaJWKSURL,
			httpClient: httpClient,
		},
		JWTToken:     jwtToken,
		EvidenceType: evidenceType,
	}
}

func (a *NvidiaCCIntermediateCertificateAttestor) CreateSignedEvidence(ctx context.Context) (*ev.SignedEvidencePiece, error) {
	intermediateCertificate, err := a.certProvider.GetCertificate(ctx, a.JWTToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get intermediate certificate: %w", err)
	}

	slog.InfoContext(ctx, "Fetched intermediate certificate from Nvidia JWKS for JWT",
		"subject", intermediateCertificate.Subject.String(),
		"not_before", intermediateCertificate.NotBefore,
		"not_after", intermediateCertificate.NotAfter)

	return &ev.SignedEvidencePiece{
		Type:      a.EvidenceType,
		Data:      intermediateCertificate.Raw,
		Signature: intermediateCertificate.Signature,
	}, nil
}

type NRASCertificateProvider struct {
	NRASURL    string
	httpClient *http.Client
}

func (p *NRASCertificateProvider) GetCertificate(ctx context.Context, jwtToken string) (*x509.Certificate, error) {
	jwks, err := p.fetchNvidiaJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	return GetCertificateForJWT(jwtToken, jwks)
}

func (p *NRASCertificateProvider) fetchNvidiaJWKS(ctx context.Context) (*JWKS, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.NRASURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS, status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWKS: %w", err)
	}

	return &jwks, nil
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	Crv string   `json:"crv"`
	X   string   `json:"x"`
	Y   string   `json:"y"`
	X5c []string `json:"x5c"`
}

func GetCertificateForJWT(jwtToken string, jwks *JWKS) (*x509.Certificate, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("failed to decode JWT header")
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, errors.New("failed to unmarshal JWT header")
	}

	kid, ok := header["kid"].(string)
	if !ok {
		return nil, errors.New("JWT header missing 'kid' claim")
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid {
			slog.Info("Found matching key in JWKS", "kid", kid)
			if len(key.X5c) == 0 {
				return nil, errors.New("no X5C certificate chain found")
			}

			if len(key.X5c) > 2 {
				return nil, errors.New("multiple certificates found in X5C")
			}

			certDer, err := base64.StdEncoding.DecodeString(key.X5c[0])
			if err != nil {
				return nil, fmt.Errorf("failed to decode certificate from base64: %w", err)
			}

			cert, err := x509.ParseCertificate(certDer)
			if err != nil {
				return nil, err
			}

			return cert, nil
		}
	}

	return nil, fmt.Errorf("no matching key found for kid: %s", kid)
}
