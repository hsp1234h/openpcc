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
	"testing"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/verify/trust"
	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/stretchr/testify/require"
)

func TestTDXCollateralAttestor_Success(t *testing.T) {
	testFS := test.TextArchiveFS(t, "testdata/gce_tdx_report.txt")
	testTDXReportPEM := test.ReadFile(t, testFS, "test_gce_tdx_report.pem")
	testTDXReport := pemReportToBytes(testTDXReportPEM)

	report, err := abi.QuoteToProto(testTDXReport)
	require.NoError(t, err)

	chain, err := attest.ExtractChainFromQuote(report)
	require.NoError(t, err)

	getter := &trust.SimpleHTTPSGetter{}

	attestor, err := attest.NewTDXCollateralAttestor(
		getter,
		chain.PCKCertificate,
	)

	require.NoError(t, err)

	ev, err := attestor.CreateSignedEvidence(t.Context())

	require.NoError(t, err)

	require.Equal(t, ev.Type, evidence.TdxCollateral)

	err = verify.TDXCollateral(t.Context(), ev)

	require.NoError(t, err)
}
