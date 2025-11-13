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
	_ "embed"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/attest/attesttest"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"
)

func setupAttestor(t *testing.T, setup *attesttest.SevSnpTestSetup) *evidence.SignedEvidencePiece {
	attestor := &attest.SEVSNPTEEAttestor{
		Nonce:         setup.Nonce,
		QuoteProvider: setup.QuoteProvider,
		Getter:        setup.Getter,
	}

	evidence, err := attestor.CreateSignedEvidence(t.Context())
	require.NoError(t, err)

	return evidence
}

func Test_VerifySEVSNPReport_Success(t *testing.T) {
	// Happy path with no revoked certs or key mismatches
	setup := attesttest.SetupSevSnpTest(t, attesttest.SevSnpTestConfig{})
	evidence := setupAttestor(t, setup)

	err := verify.SEVSNPReport(t.Context(), evidence, true, setup.Getter)
	require.NoError(t, err)
}

func Test_VerifySEVSNPReport_FailureArkRevoked(t *testing.T) {
	// Test with ARK certificate revoked
	setup := attesttest.SetupSevSnpTest(t, attesttest.SevSnpTestConfig{ArkRevoked: true})
	evidence := setupAttestor(t, setup)

	err := verify.SEVSNPReport(t.Context(), evidence, true, setup.Getter)
	require.Error(t, err, "should fail when ARK is revoked")
}

func Test_VerifySEVSNPReport_FailureAskRevoked(t *testing.T) {
	// Test with ASK certificate revoked
	setup := attesttest.SetupSevSnpTest(t, attesttest.SevSnpTestConfig{AskRevoked: true})
	evidence := setupAttestor(t, setup)

	err := verify.SEVSNPReport(t.Context(), evidence, true, setup.Getter)
	require.Error(t, err, "should fail when ASK is revoked")
}

func Test_VerifySEVSNPReport_FailureSignerRootMismatch(t *testing.T) {
	// Test with a mismatched VCEK key
	setup := attesttest.SetupSevSnpTest(t, attesttest.SevSnpTestConfig{UseMismatchedVcekKey: true})
	evidence := setupAttestor(t, setup)

	err := verify.SEVSNPReport(t.Context(), evidence, true, setup.Getter)
	require.Error(t, err, "should fail with signer root mismatch")
}
