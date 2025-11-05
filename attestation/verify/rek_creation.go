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
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/openpcc/openpcc/attestation/evidence"
)

func REKCreation(
	ctx context.Context,
	attestationKey *rsa.PublicKey,
	signedEvidencePiece *evidence.SignedEvidencePiece,
) (*tpm2.TPM2BAttest, error) {
	info, err := tpm2.Unmarshal[tpm2.TPM2BAttest](signedEvidencePiece.Data)

	if err != nil {
		return nil, err
	}
	infoContents, err := info.Contents()

	if err != nil {
		return nil, err
	}

	certify, err := infoContents.Attested.Creation()

	if err != nil {
		return nil, err
	}

	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](signedEvidencePiece.Signature)

	if err != nil {
		return nil, err
	}

	attestHash := sha256.Sum256(tpm2.Marshal(infoContents))

	rsassa, err := sig.Signature.RSASSA()
	if err != nil {
		return nil, err
	}

	err = rsa.VerifyPKCS1v15(attestationKey, crypto.SHA256, attestHash[:], rsassa.Sig.Buffer)

	if err != nil {
		return nil, err
	}

	slog.DebugContext(ctx, "Verified relationship between REK and attestation key", "attestation_key", attestationKey, "rek", certify.ObjectName)

	return info, nil
}
