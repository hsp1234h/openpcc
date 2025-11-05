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
package verify

import (
	"context"
	"fmt"

	spb "github.com/google/go-sev-guest/proto/sevsnp"
	sv "github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/openpcc/openpcc/attestation/evidence"
	"google.golang.org/protobuf/proto"
)

func SEVSNPReport(
	ctx context.Context,
	signedEvidencePiece *evidence.SignedEvidencePiece,
	checkRevocations bool,
	getter trust.HTTPSGetter,
) error {
	attestation := &spb.Attestation{}
	err := proto.Unmarshal(signedEvidencePiece.Data, attestation)

	if err != nil {
		return fmt.Errorf("failed to parse SEV-SNP report (%v): %w", signedEvidencePiece.Data, err)
	}

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
	return nil
}
