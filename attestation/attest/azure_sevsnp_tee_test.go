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
	"encoding/pem"
	"testing"

	sevtest "github.com/google/go-sev-guest/testing"
	"github.com/stretchr/testify/require"

	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/verify"
	test "github.com/openpcc/openpcc/inttest"
)

func Test_AzureSEVSNPTEEAttestor_Success(t *testing.T) {
	sevFS := test.TextArchiveFS(t, "testdata/sev_certificates.txt")
	reportFS := test.TextArchiveFS(t, "testdata/azure_sevsnp_report.txt")
	testAMDGenoaCRL := test.ReadFile(t, sevFS, "test_amd_genoa_crl.pem")
	testAMDMilanCRL := test.ReadFile(t, sevFS, "test_amd_milan_crl.pem")
	testAzureSEVSNPReportPEM := test.ReadFile(t, reportFS, "test_azure_sevsnp_report.pem")
	testAMDSEVMilanCertChainPEM := test.ReadFile(t, sevFS, "test_amd_sev_milan_root_certs.pem")
	testAMDSEVGenoaCertChainPEM := test.ReadFile(t, sevFS, "test_amd_sev_genoa_root_certs.pem")
	testAMDSEVVCEK := test.ReadFile(t, sevFS, "test_vcek.pem")

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	block, _ := pem.Decode(testAzureSEVSNPReportPEM)
	require.NotNil(t, block)

	mocktpm := &TPMNVWrapper{
		realtpm:       thetpm,
		responseBytes: block.Bytes,
	}

	// Parse the VCEK as it needs to be returned from the api in DER
	vcek, _ := pem.Decode(testAMDSEVVCEK)
	require.NotNil(t, vcek)

	// Parse the CRLs
	genoaCrlDer, _ := pem.Decode(testAMDGenoaCRL)
	require.NotNil(t, genoaCrlDer)

	milanCrlDer, _ := pem.Decode(testAMDMilanCRL)
	require.NotNil(t, milanCrlDer)

	getter := sevtest.SimpleGetter(map[string][]byte{
		"https://kdsintf.amd.com/vcek/v1/Genoa/c70912d8d216bd3f403e97bda2d476924b962752119263a3c8dba9fc40badfc99038d2352aae22520a9003b4262e1cc3136d035b42e4b022b4196f95981a45c6?blSPL=10&teeSPL=0&snpSPL=23&ucodeSPL=84": vcek.Bytes,
		"https://kdsintf.amd.com/vcek/v1/Milan/cert_chain": testAMDSEVMilanCertChainPEM,
		"https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain": testAMDSEVGenoaCertChainPEM,
		"https://kdsintf.amd.com/vcek/v1/Milan/crl":        milanCrlDer.Bytes,
		"https://kdsintf.amd.com/vcek/v1/Genoa/crl":        genoaCrlDer.Bytes,
	})

	attestor := attest.NewAzureSEVSNPTEEAttestorWithGetter(
		mocktpm,
		make([]byte, 64),
		getter,
	)
	se, err := attestor.CreateSignedEvidence(t.Context())

	require.NoError(t, err)
	require.NotNil(t, se)

	err = verify.SEVSNPReport(t.Context(), se, true, getter)
	require.NoError(t, err)
}
