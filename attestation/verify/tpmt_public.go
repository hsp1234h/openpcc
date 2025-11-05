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
	"bytes"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/openpcc/openpcc/attestation/evidence"
	cstpm "github.com/openpcc/openpcc/tpm"
)

func TPMT(
	certifiedName tpm2.TPM2BName,
	signedEvidencePiece *evidence.SignedEvidencePiece,
	desiredPcrValues evidence.PCRValues,
) error {
	tpmtPublic, err := tpm2.Unmarshal[tpm2.TPMTPublic](signedEvidencePiece.Data)

	if err != nil {
		return fmt.Errorf("failed to unmarshal TPMT public: %w", err)
	}

	expectedName, err := tpm2.ObjectName(tpmtPublic)

	if err != nil {
		return fmt.Errorf("failed to get object name: %w", err)
	}

	if !bytes.Equal(expectedName.Buffer, certifiedName.Buffer) {
		return errors.New("certified name does not match expected name")
	}

	desiredAuthPolicyDigest, err := cstpm.GetSoftwarePCRPolicyDigest(desiredPcrValues.Values)

	if err != nil {
		return fmt.Errorf("failed to get software PCR policy digest: %w", err)
	}

	if !bytes.Equal(tpmtPublic.AuthPolicy.Buffer, *desiredAuthPolicyDigest) {
		return fmt.Errorf("attested key does not enforce desired PCR values, expected %x, got %x",
			*desiredAuthPolicyDigest, tpmtPublic.AuthPolicy.Buffer)
	}

	return nil
}
