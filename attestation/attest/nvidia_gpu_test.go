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
package attest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/stretchr/testify/require"
)

type MockGPUAttestationProvider struct {
	AttestFunc func(ctx context.Context, nonce []byte) (*gonvtrust.AttestationResult, error)
}

func (m *MockGPUAttestationProvider) Attest(ctx context.Context, nonce []byte) (*gonvtrust.AttestationResult, error) {
	return m.AttestFunc(ctx, nonce)
}

func Test_NvidiaCCAttestorName(t *testing.T) {
	attestor, err := attest.NewNVidiaAttestor(&MockGPUAttestationProvider{}, evidence.NvidiaETA, make([]byte, 32))
	require.NoError(t, err)
	require.Equal(t, "NvidiaCCAttestor", attestor.Name())
}

func Test_CreateSignedEvidence_Success(t *testing.T) {
	nonce := make([]byte, 32)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"gpu": "NVIDIA A100",
		"sub": "attestation",
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	jwtToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return []byte("test-secret"), nil
	})
	require.NoError(t, err)

	mockProvider := &MockGPUAttestationProvider{
		AttestFunc: func(ctx context.Context, n []byte) (*gonvtrust.AttestationResult, error) {
			require.Equal(t, nonce, n)

			return &gonvtrust.AttestationResult{
				Result:   true,
				JWTToken: jwtToken,
				DevicesTokens: map[string]string{
					"GPU-0": "mock-gpu-token",
				},
			}, nil
		},
	}

	attestor, err := attest.NewNVidiaAttestor(mockProvider, evidence.NvidiaETA, nonce)
	require.NoError(t, err)

	evidencePiece, err := attestor.CreateSignedEvidence(t.Context())
	require.NoError(t, err)
	require.NotNil(t, evidencePiece)
	require.Equal(t, evidence.NvidiaETA, evidencePiece.Type)
}

func Test_CreateSignedEvidence_InvalidNonceSize(t *testing.T) {
	nonce := make([]byte, 16)

	mockProvider := &MockGPUAttestationProvider{}

	attestor, err := attest.NewNVidiaAttestor(mockProvider, evidence.NvidiaETA, nonce)
	require.NoError(t, err)

	evidencePiece, err := attestor.CreateSignedEvidence(t.Context())
	require.Error(t, err)
	require.Nil(t, evidencePiece)
	require.Contains(t, err.Error(), "TDX device requires 32 bytes")
}

func Test_CreateSignedEvidence_GetRemoteEvidenceError(t *testing.T) {
	nonce := make([]byte, 32)

	mockProvider := &MockGPUAttestationProvider{
		AttestFunc: func(ctx context.Context, n []byte) (*gonvtrust.AttestationResult, error) {
			return nil, errors.New("failed to get evidence")
		},
	}

	attestor, err := attest.NewNVidiaAttestor(mockProvider, evidence.NvidiaETA, nonce)
	require.NoError(t, err)

	evidencePiece, err := attestor.CreateSignedEvidence(t.Context())
	require.Error(t, err)
	require.Nil(t, evidencePiece)
	require.Contains(t, err.Error(), "failed to get remote evidence")
}

func Test_CreateSignedEvidence_AttestRemoteEvidenceError(t *testing.T) {
	nonce := make([]byte, 32)

	mockProvider := &MockGPUAttestationProvider{
		AttestFunc: func(ctx context.Context, n []byte) (*gonvtrust.AttestationResult, error) {
			return nil, errors.New("attestation failed")
		},
	}

	attestor, err := attest.NewNVidiaAttestor(mockProvider, evidence.NvidiaETA, nonce)
	require.NoError(t, err)

	evidencePiece, err := attestor.CreateSignedEvidence(t.Context())
	require.Error(t, err)
	require.Nil(t, evidencePiece)
	require.Contains(t, err.Error(), "failed to get remote evidence")
}

func Test_CreateSignedEvidence_AttestationResultFalse(t *testing.T) {
	nonce := make([]byte, 32)

	mockProvider := &MockGPUAttestationProvider{
		AttestFunc: func(ctx context.Context, n []byte) (*gonvtrust.AttestationResult, error) {
			return &gonvtrust.AttestationResult{
				Result: false,
			}, nil
		},
	}

	attestor, err := attest.NewNVidiaAttestor(mockProvider, evidence.NvidiaETA, nonce)
	require.NoError(t, err)

	evidencePiece, err := attestor.CreateSignedEvidence(t.Context())
	require.Error(t, err)
	require.Nil(t, evidencePiece)
	require.Contains(t, err.Error(), "attestation failed")
}

func Test_CreateSignedEvidence_EvidencePieceCreationError(t *testing.T) {
	nonce := make([]byte, 32)

	mockToken := &jwt.Token{
		Raw: "invalid-format",
	}

	mockProvider := &MockGPUAttestationProvider{
		AttestFunc: func(ctx context.Context, n []byte) (*gonvtrust.AttestationResult, error) {
			return &gonvtrust.AttestationResult{
				Result:   true,
				JWTToken: mockToken,
				DevicesTokens: map[string]string{
					"GPU-0": "mock-gpu-token",
				},
			}, nil
		},
	}

	attestor, err := attest.NewNVidiaAttestor(mockProvider, evidence.NvidiaETA, nonce)
	require.NoError(t, err)

	evidencePiece, err := attestor.CreateSignedEvidence(t.Context())
	require.Error(t, err)
	require.Nil(t, evidencePiece)
	require.Contains(t, err.Error(), "failed to create evidence piece")
}
