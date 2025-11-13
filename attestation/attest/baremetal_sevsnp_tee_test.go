// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security
//
// Licensed under the Confident Security Limited License, the
// terms and conditions of which are set forth in the "LICENSE"
// file included in the root directory of this code repository
// (the "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at
//
// license.confident.security/limited/v1
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package attest_test

import (
	_ "embed"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/require"

	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/attest/attesttest"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"
	cstpm "github.com/openpcc/openpcc/tpm"
)

func setupBareMetalTEEEvidence(t *testing.T, setup *attesttest.SevSnpTestSetup) *evidence.SignedEvidencePiece {
	attestor := &attest.BareMetalSEVSNPTEEAttestor{
		Nonce:         setup.Nonce,
		QuoteProvider: setup.QuoteProvider,
		Getter:        setup.Getter,
	}

	evidence, err := attestor.CreateSignedEvidence(t.Context())
	require.NoError(t, err)

	return evidence
}

func setupTpmtEvidence(t *testing.T, thetpm transport.TPMCloser) *evidence.SignedEvidencePiece {
	public := tpm2.New2B(cstpm.GetRSASSASigningEKTemplate())

	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{},
	}

	createSigningCommand := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      public,
		CreationPCR:   pcrSelection,
	}
	createSigningResponse, err := createSigningCommand.Execute(thetpm)

	require.NoError(t, err)

	attestor := attest.NewTPMTPublicAttestor(thetpm, tpmutil.Handle(createSigningResponse.ObjectHandle), evidence.TpmtPublic)

	se, err := attestor.CreateSignedEvidence(t.Context())

	require.NoError(t, err)
	require.NotNil(t, se)
	return se

}

func Test_VerifyBareMetalSEVSNPReport_Success(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	// Happy path with no revoked certs or key mismatches
	setup := attesttest.SetupSevSnpTest(t, attesttest.SevSnpTestConfig{UseExtendedReport: true, TPM: thetpm})
	evidence := setupBareMetalTEEEvidence(t, setup)

	tpmtEvidence := setupTpmtEvidence(t, thetpm)

	err = verify.BareMetalSEVSNPReport(t.Context(), evidence, true, setup.Getter)
	require.NoError(t, err)

	akPub, err := verify.BareMetalSEVSNPAKPub(t.Context(), evidence, tpmtEvidence)
	require.NoError(t, err)
	require.NotNil(t, akPub)
}

func Test_VerifyBareMetalSEVSNPReport_FailureBadReportData(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	setup := attesttest.SetupSevSnpTest(t, attesttest.SevSnpTestConfig{
		UseExtendedReport: true,
		UseBadReportData:  true,
		TPM:               thetpm})
	evidence := setupBareMetalTEEEvidence(t, setup)

	err = verify.BareMetalSEVSNPReport(t.Context(), evidence, true, setup.Getter)
	require.Error(t, err, "should fail with bad report data")
}

func Test_VerifyBareMetalSEVSNPReport_FailureBadAK(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	setup := attesttest.SetupSevSnpTest(t, attesttest.SevSnpTestConfig{
		UseExtendedReport: true,
		UseMismatchedAK:   true,
		TPM:               thetpm})
	evidence := setupBareMetalTEEEvidence(t, setup)

	tpmtEvidence := setupTpmtEvidence(t, thetpm)

	err = verify.BareMetalSEVSNPReport(t.Context(), evidence, true, setup.Getter)
	require.NoError(t, err)

	_, err = verify.BareMetalSEVSNPAKPub(t.Context(), evidence, tpmtEvidence)
	require.Error(t, err, "should fail with mismatched TPMT public key")
}

func Test_VerifyBareMetalSEVSNPReport_FailureArkRevoked(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	setup := attesttest.SetupSevSnpTest(t, attesttest.SevSnpTestConfig{
		UseExtendedReport: true,
		ArkRevoked:        true,
		TPM:               thetpm})
	evidence := setupBareMetalTEEEvidence(t, setup)

	err = verify.BareMetalSEVSNPReport(t.Context(), evidence, true, setup.Getter)
	require.Error(t, err, "should fail when ARK is revoked")
}

func Test_VerifyBareMetalSEVSNPReport_FailureAskRevoked(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	setup := attesttest.SetupSevSnpTest(t, attesttest.SevSnpTestConfig{
		UseExtendedReport: true,
		AskRevoked:        true,
		TPM:               thetpm})
	evidence := setupBareMetalTEEEvidence(t, setup)

	err = verify.BareMetalSEVSNPReport(t.Context(), evidence, true, setup.Getter)
	require.Error(t, err, "should fail when ASK is revoked")
}

func Test_VerifyBareMetalSEVSNPReport_FailureSignerRootMismatch(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	setup := attesttest.SetupSevSnpTest(t, attesttest.SevSnpTestConfig{
		UseExtendedReport:    true,
		UseMismatchedVcekKey: true,
		TPM:                  thetpm})
	evidence := setupBareMetalTEEEvidence(t, setup)

	err = verify.BareMetalSEVSNPReport(t.Context(), evidence, true, setup.Getter)
	require.Error(t, err, "should fail with signer root mismatch")
}
