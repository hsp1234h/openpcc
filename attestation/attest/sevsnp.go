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
	"fmt"

	"github.com/openpcc/openpcc/attestation/evidence"

	sabi "github.com/google/go-sev-guest/abi"
)

func RawReportToSignedEvidencePiece(raw []byte) (*evidence.SignedEvidencePiece, error) {
	if len(raw) < sabi.ReportSize {
		return nil, fmt.Errorf("raw report is too small: %d bytes", len(raw))
	}

	// The first 64 bytes are the report
	reportBytes := raw[0:sabi.ReportSize]
	// The rest is the certificate
	certBytes := raw[sabi.ReportSize:]

	report, err := sabi.ReportToProto(reportBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse attestation report: %w", err)
	}

	certs := new(sabi.CertTable)
	if err := certs.Unmarshal(certBytes); err != nil {
		return nil, fmt.Errorf("could not parse certificate table: %w", err)
	}

	raw, err = sabi.ReportToAbiBytes(report)
	if err != nil {
		return nil, fmt.Errorf("could not interpret report: %w", err)
	}

	signature, err := sabi.ReportToSignatureDER(reportBytes)
	if err != nil {
		return nil, err
	}

	return &evidence.SignedEvidencePiece{
		Type:      evidence.SevSnpReport,
		Data:      raw,
		Signature: signature,
	}, nil
}
