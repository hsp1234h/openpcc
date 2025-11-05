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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCertificateProvider struct {
	cert *x509.Certificate
	err  error
}

func (m *mockCertificateProvider) GetCertificate(_ context.Context, _ string) (*x509.Certificate, error) {
	return m.cert, m.err
}

func newTestCertificate() (*x509.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

func TestNvidiaCCIntermediateCertificateAttestor_CreateSignedEvidence(t *testing.T) {
	testCert, err := newTestCertificate()
	require.NoError(t, err)

	const testJWT = "test-jwt-token"

	tests := []struct {
		name           string
		mockProvider   *mockCertificateProvider
		expectedError  string
		expectEvidence bool
	}{
		{
			name: "successful evidence creation",
			mockProvider: &mockCertificateProvider{
				cert: testCert,
				err:  nil,
			},
			expectEvidence: true,
		},
		{
			name: "certificate provider returns error",
			mockProvider: &mockCertificateProvider{
				cert: nil,
				err:  errors.New("provider error"),
			},
			expectedError: "failed to get intermediate certificate: provider error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestor := &NvidiaCCIntermediateCertificateAttestor{
				certProvider: tt.mockProvider,
				JWTToken:     testJWT,
				EvidenceType: evidence.NvidiaCCIntermediateCertificate,
			}

			sev, err := attestor.CreateSignedEvidence(t.Context())

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, sev)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, sev)
				assert.Equal(t, evidence.NvidiaCCIntermediateCertificate, sev.Type)
				assert.Equal(t, testCert.Raw, sev.Data)
				assert.Equal(t, testCert.Signature, sev.Signature)
			}
		})
	}
}

func TestNRASCertificateProvider_GetCertificate(t *testing.T) {
	testCert, err := newTestCertificate()
	require.NoError(t, err)
	testCertPEM := base64.StdEncoding.EncodeToString(testCert.Raw)

	jwtToken := createTestJWT("test-kid", map[string]any{})

	tests := []struct {
		name          string
		mockHandler   http.HandlerFunc
		expectedError string
		expectCert    bool
	}{
		{
			name: "successful GetCertificate",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				jwks := JWKS{
					Keys: []JWK{
						{Kid: "test-kid", X5c: []string{testCertPEM}},
					},
				}
				json.NewEncoder(w).Encode(jwks)
			},
			expectCert: true,
		},
		{
			name: "fetchNvidiaJWKS fails - server error",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedError: "failed to fetch JWKS, status code: 500",
		},
		{
			name: "fetchNvidiaJWKS fails - bad json",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("not-json"))
			},
			expectedError: "failed to unmarshal JWKS",
		},
		{
			name: "GetCertificateForJWT fails - no matching kid",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				jwks := JWKS{
					Keys: []JWK{
						{Kid: "another-kid", X5c: []string{testCertPEM}},
					},
				}
				json.NewEncoder(w).Encode(jwks)
			},
			expectedError: "no matching key found for kid: test-kid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.mockHandler)
			defer server.Close()

			provider := &NRASCertificateProvider{NRASURL: server.URL, httpClient: server.Client()}
			cert, err := provider.GetCertificate(t.Context(), jwtToken)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, cert)
			} else {
				assert.NoError(t, err)
				if tt.expectCert {
					assert.NotNil(t, cert)
					assert.Equal(t, testCert.Raw, cert.Raw)
				} else {
					assert.Nil(t, cert)
				}
			}
		})
	}
}

func TestGetCertificateForJWT(t *testing.T) {
	testCert, err := newTestCertificate()
	require.NoError(t, err)
	testCertPEM := base64.StdEncoding.EncodeToString(testCert.Raw)

	tests := []struct {
		name          string
		jwtToken      string
		jwks          *JWKS
		expectedError string
		expectCert    bool
	}{
		{
			name:     "valid JWT and JWKS",
			jwtToken: createTestJWT("test-kid", map[string]any{"sub": "user"}),
			jwks: &JWKS{
				Keys: []JWK{
					{Kid: "test-kid", X5c: []string{testCertPEM}},
				},
			},
			expectCert: true,
		},
		{
			name:          "invalid JWT format - too few parts",
			jwtToken:      "invalid.token",
			jwks:          &JWKS{},
			expectedError: "invalid JWT format",
		},
		{
			name:          "invalid JWT format - too many parts",
			jwtToken:      "invalid.token.format.again",
			jwks:          &JWKS{},
			expectedError: "invalid JWT format",
		},
		{
			name:          "failed to decode JWT header - invalid base64",
			jwtToken:      "%%%%%.payload.signature",
			jwks:          &JWKS{},
			expectedError: "failed to decode JWT header",
		},
		{
			name:          "failed to unmarshal JWT header - not json",
			jwtToken:      base64.RawURLEncoding.EncodeToString([]byte("not-json")) + ".payload.signature",
			jwks:          &JWKS{},
			expectedError: "failed to unmarshal JWT header",
		},
		{
			name: "JWT header missing kid claim",
			jwtToken: func() string {
				header := map[string]any{"alg": "ES256", "typ": "JWT"}
				headerBytes, _ := json.Marshal(header)
				headerEnc := base64.RawURLEncoding.EncodeToString(headerBytes)
				return headerEnc + ".payload.signature"
			}(),
			jwks:          &JWKS{Keys: []JWK{{Kid: "some-kid", X5c: []string{testCertPEM}}}},
			expectedError: "JWT header missing 'kid' claim",
		},
		{
			name:          "no matching key found for kid",
			jwtToken:      createTestJWT("unknown-kid", map[string]any{}),
			jwks:          &JWKS{Keys: []JWK{{Kid: "test-kid", X5c: []string{testCertPEM}}}},
			expectedError: "no matching key found for kid: unknown-kid",
		},
		{
			name:          "no X5C certificate chain found",
			jwtToken:      createTestJWT("test-kid", map[string]any{}),
			jwks:          &JWKS{Keys: []JWK{{Kid: "test-kid", X5c: nil}}},
			expectedError: "no X5C certificate chain found",
		},
		{
			name:          "empty X5C certificate chain",
			jwtToken:      createTestJWT("test-kid", map[string]any{}),
			jwks:          &JWKS{Keys: []JWK{{Kid: "test-kid", X5c: []string{}}}},
			expectedError: "no X5C certificate chain found",
		},
		{
			name:          "multiple certificates found in X5C",
			jwtToken:      createTestJWT("test-kid", map[string]any{}),
			jwks:          &JWKS{Keys: []JWK{{Kid: "test-kid", X5c: []string{testCertPEM, "cert2", "cert3"}}}},
			expectedError: "multiple certificates found in X5C",
		},
		{
			name:          "incorrectly encoded certificate",
			jwtToken:      createTestJWT("test-kid", map[string]any{}),
			jwks:          &JWKS{Keys: []JWK{{Kid: "test-kid", X5c: []string{"invalid PEM data"}}}},
			expectedError: "failed to decode certificate from base64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := GetCertificateForJWT(tt.jwtToken, tt.jwks)

			if tt.expectedError != "" {
				assert.Error(t, err)

				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, cert)
			} else {
				assert.NoError(t, err)
				if tt.expectCert {
					assert.NotNil(t, cert)
					assert.Equal(t, testCert.Raw, cert.Raw)
				} else {
					assert.Nil(t, cert)
				}
			}
		})
	}
}

func createTestJWT(kid string, payload map[string]any) string {
	header := map[string]any{
		"alg": "EC384",
		"typ": "JWT",
		"kid": kid,
	}
	headerBytes, _ := json.Marshal(header)
	headerEnc := base64.RawURLEncoding.EncodeToString(headerBytes)

	payloadBytes, _ := json.Marshal(payload)
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadBytes)

	unsignedToken := headerEnc + "." + payloadEnc

	return unsignedToken + ".dummySignature"
}
