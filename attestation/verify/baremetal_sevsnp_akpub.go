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
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"reflect"

	sabi "github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/uuid"
	"github.com/openpcc/openpcc/attestation/evidence"
	"google.golang.org/protobuf/proto"
)

var SVSMAttestVtpmGUID = uuid.MustParse("c476f1eb-0123-45a5-9641-b4e7dde5bfe3")

// BareMetalSEVSNPAKPub derives the public key from signed evidence pieces containing
// the SEV-SNP report and TPMTPublic evidence, respectively.
//   - First, we retrieve the SVSM services manifest from the SEV-SNP evidence,
//     which contains a table mapping service GUIDs to a byte slice of the TPMT public area.
//     Currently, the only SVSM service returned is the vTPM service, whose TPMT public
//     should match the TPMT Public of the attestation key because they were created
//     from the same TPMTPublic template.
//   - Next, we unmarshal the TPMT Public from the GUID table entry for vTPM and compare
//     it to the TPMT Public in the TPMTPublic evidence (which represents the AK)
//   - Finally, we convert the unique field of the TPMT public to an RSA public key
func BareMetalSEVSNPAKPub(
	_ context.Context,
	reportEvidence *evidence.SignedEvidencePiece,
	tpmtPublicEvidence *evidence.SignedEvidencePiece,
) (*rsa.PublicKey, error) {
	attestation := &spb.Attestation{}
	if reportEvidence.Type != evidence.SevSnpExtendedReport {
		return nil, errors.New("failed to parse SEV-SNP report: expected SevSnpExtendedReport")
	}

	attestationBytes := make([]byte, len(reportEvidence.Data)-sabi.ReportDataSize)
	copy(attestationBytes, reportEvidence.Data[sabi.ReportDataSize:])
	err := proto.Unmarshal(attestationBytes, attestation)

	if err != nil {
		return nil, fmt.Errorf("failed to parse SEV-SNP report (%v): %w", attestationBytes, err)
	}

	// Parse the services manifest into a GUID table and extract the vTPM entry,
	// which is our expected TPMT public value
	manifest, err := sabi.ServicesManifestFromProto(attestation.GetServicesManifest())
	if err != nil {
		return nil, fmt.Errorf("failed to parse SEV-SNP GUID table: %w", err)
	}

	vtpmEntry, err := manifest.GetEntry(SVSMAttestVtpmGUID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SEV-SNP GUID table: %w", err)
	}

	expectedTpmtPublic, err := tpm2.Unmarshal[tpm2.TPMTPublic](vtpmEntry.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal TPMT public from services manifest: %w", err)
	}

	// Unmarshal the TPMT public from the TPMTPublic evidence, which is the TPMT public
	// of the attestation key
	tpmtPublic, err := tpm2.Unmarshal[tpm2.TPMTPublic](tpmtPublicEvidence.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal TPMT public: %w", err)
	}

	// both TPMTPublic should be equal because they were created with the same TPMTPublic template,
	// and according to the TPM 2.0 spec part 3 section 24.1, "If this command is called multiple times
	// with the same inPublic parameter, inSensitive.data, and PrimarySeed, the TPM shall produce the same Primary Object."
	if !reflect.DeepEqual(tpmtPublic, expectedTpmtPublic) {
		return nil, errors.New("the TPMT public key does not match the expected value from the SEV-SNP report")
	} else {
		slog.Debug("verified attestation key TPMT public matches TPMT public in the services manifest")
	}

	// Convert unique field of TPMT public to RSA public key
	tpmtPublicKey, err := tpmtPublic.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("failed to extract RSA public key from TPMT public: %w", err)
	}
	rsaDetail, err := tpmtPublic.Parameters.RSADetail()
	if err != nil {
		return nil, fmt.Errorf("failed to extract RSA detail from TPMT public: %w", err)
	}
	akPubKey, err := tpm2.RSAPub(rsaDetail, tpmtPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert TPMT public to RSA public key: %w", err)
	}

	return akPubKey, nil
}
