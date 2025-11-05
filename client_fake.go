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

package openpcc

import (
	"log/slog"

	"github.com/openpcc/openpcc/attestation/verify"
)

// buildConfig contains build specific configuration.
type buildConfig struct {
	fakeAttestationSecret string
}

// WithFakeAttestationSecret sets the secret to use when using fake attestation.
//
// This secret needs to match the secret used on the compute node.
func WithFakeAttestationSecret(secret string) Option {
	return func(_ *Client, _ *scratch, cfg *Config) error {
		cfg.build.fakeAttestationSecret = secret
		return nil
	}
}

// newVerifier creates a new verifier.
func newVerifier(cfg Config, _ TransparencyVerifier) verify.Verifier {
	if cfg.build.fakeAttestationSecret != "" {
		slog.Warn("using fake attestation verifier!")
		return verify.NewFakeVerifier([]byte(cfg.build.fakeAttestationSecret))
	}
	// Note: make sure any changes after the fake verifier, are mirrored in `client_real.go`.
	return verify.NewTemporaryVerifier()
}
