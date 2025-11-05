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
//go:build !include_fake_attestation

package openpcc

import (
	"github.com/openpcc/openpcc/attestation/verify"
)

// buildConfig contains build specific configuration (none in case of real builds).
type buildConfig struct{}

func newVerifier(
	cfg Config,
	transparencyVerifier TransparencyVerifier,
) verify.Verifier {
	//nolint
	cfg.build = buildConfig{} // can't seem to add nolint line above buildConfig. Assign to make linters happy.
	// Note: make sure any changes here are mirrored in `client_fake.go`.
	return verify.NewConfidentSecurityVerifier(transparencyVerifier, cfg.TransparencyIdentityPolicy)
}
