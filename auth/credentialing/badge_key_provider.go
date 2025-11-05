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

package credentialing

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"crypto/ed25519"
)

type BadgeKeyProvider interface {
	PrivateKey() (ed25519.PrivateKey, error)
}

func NewBadgeKeyProvider(cfg *Config) (BadgeKeyProvider, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}
	if cfg.BadgeKey == "" {
		return nil, errors.New("empty badge key")
	}

	decoded, err := base64.StdEncoding.DecodeString(cfg.BadgeKey)
	if err != nil {
		return nil, fmt.Errorf("badge key provider failed to base64 decode: %w", err)
	}

	key, err := ParsePrivateKey(string(decoded))
	if err != nil {
		return nil, fmt.Errorf("currency key provider failed to create: %w", err)
	}

	return &badgeKeyProvider{
		privateKey: key,
	}, nil
}

func ParsePrivateKey(pemStr string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	privKeyed25519, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("failed to convert parsed private key into an ed25519 private key")
	}

	return privKeyed25519, nil
}

type badgeKeyProvider struct {
	privateKey ed25519.PrivateKey
}

func (k *badgeKeyProvider) PrivateKey() (ed25519.PrivateKey, error) {
	return k.privateKey, nil
}
