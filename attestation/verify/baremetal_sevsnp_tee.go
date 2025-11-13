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
package verify

import (
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	sabi "github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	sv "github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/openpcc/openpcc/attestation/evidence"
	"google.golang.org/protobuf/proto"
)

func BareMetalSEVSNPReport(
	ctx context.Context,
	signedEvidencePiece *evidence.SignedEvidencePiece,
	checkRevocations bool,
	getter trust.HTTPSGetter,
) error {
	attestation := &spb.Attestation{}
	var snpNonce = make([]byte, sabi.ReportDataSize)
	copy(snpNonce, signedEvidencePiece.Data[:sabi.ReportDataSize])

	var attestationBytes = make([]byte, len(signedEvidencePiece.Data)-sabi.ReportDataSize)
	copy(attestationBytes, signedEvidencePiece.Data[sabi.ReportDataSize:])
	err := proto.Unmarshal(attestationBytes, attestation)

	if err != nil {
		return fmt.Errorf("failed to parse SEV-SNP report (%v): %w", attestationBytes, err)
	}

	// this call will verify that the report was signed by the VCEK
	err = sv.SnpAttestationContext(
		ctx,
		attestation,
		&sv.Options{
			DisableCertFetching: true,
			CheckRevocations:    checkRevocations,
			Getter:              getter,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to verify SEV-SNP report: %w", err)
	}

	// parse the services manifest into a GUID table and verify that the report data
	// in the SEV-SNP report matches the hash of the nonce + guid table
	manifest, err := sabi.ServicesManifestFromProto(attestation.GetServicesManifest())
	if err != nil {
		return fmt.Errorf("failed to parse SEV-SNP GUID table: %w", err)
	}

	manifestBytes, err := manifest.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal SEV-SNP GUID table: %w", err)
	}

	hash := sha512.Sum512(append(snpNonce, manifestBytes...))
	reportData := attestation.Report.ReportData
	if !slices.Equal(reportData, hash[:]) {
		return errors.New("failed to verify SEV-SNP report:report data does not match")
	} else {
		slog.Debug("Verified report data in SEV-SNP extended report")
	}

	return nil
}
