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
//go:build include_fake_attestation

package attest

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/openpcc/openpcc/attestation/evidence"
)

// FakeAttestor creates some random data and signs it with the given secret.
type FakeAttestor struct {
	sharedSecret []byte
}

func NewFakeAttestor(secret []byte) Attestor {
	return &FakeAttestor{
		sharedSecret: secret,
	}
}

func (*FakeAttestor) Name() string {
	return "fakeAttestor"
}

func (a *FakeAttestor) CreateSignedEvidence(_ context.Context) (*evidence.SignedEvidencePiece, error) {
	nonce := make([]byte, 128)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create nonce: %w", err)
	}

	signature, err := sign(a.sharedSecret, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return &evidence.SignedEvidencePiece{
		Type:      evidence.EvidenceTypeUnspecified,
		Data:      nonce,
		Signature: signature,
	}, nil
}

func sign(secret []byte, elements ...[]byte) ([]byte, error) {
	mac := hmac.New(sha256.New, secret)
	for i, element := range elements {
		_, err := mac.Write(element)
		if err != nil {
			return nil, fmt.Errorf("failed to write %d to mac: %w", i, err)
		}
	}

	return mac.Sum(nil), nil
}
