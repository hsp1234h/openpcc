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
	"errors"
	"sort"

	"github.com/ccoveille/go-safecast"
	"github.com/google/go-tpm/tpm2"
	"github.com/openpcc/openpcc/attestation/evidence"
)

func TPMQuote(
	_ context.Context,
	attestationKey *rsa.PublicKey,
	signedEvidencePiece *evidence.SignedEvidencePiece,
) (*evidence.PCRValues, error) {
	tpmQuoteProto := evidence.TPMQuoteAttestation{}

	err := tpmQuoteProto.UnmarshalBinary(signedEvidencePiece.Data)

	if err != nil {
		return nil, err
	}
	tpms, err := tpm2.Unmarshal[tpm2.TPMSAttest](tpmQuoteProto.TmpstAttestQuote)

	if err != nil {
		return nil, err
	}

	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](signedEvidencePiece.Signature)

	if err != nil {
		return nil, err
	}

	attestHash := sha256.Sum256(tpm2.Marshal(tpms))

	rsassa, err := sig.Signature.RSASSA()
	if err != nil {
		return nil, err
	}

	err = rsa.VerifyPKCS1v15(attestationKey, crypto.SHA256, attestHash[:], rsassa.Sig.Buffer)

	if err != nil {
		return nil, err
	}

	var concatenatedPCRs []byte
	orderedPCRIndices := make([]int, 0, len(tpmQuoteProto.PCRValues.Values))
	for k := range tpmQuoteProto.PCRValues.Values {
		orderedPCRIndices = append(orderedPCRIndices, int(k))
	}
	sort.Ints(orderedPCRIndices) // assuming keys are strings

	for _, k := range orderedPCRIndices {
		kSafe, err := safecast.ToUint32(k)
		if err != nil {
			return nil, err
		}
		concatenatedPCRs = append(concatenatedPCRs, tpmQuoteProto.PCRValues.Values[kSafe]...)
	}

	expectedPCRDigest := sha256.Sum256(concatenatedPCRs)

	attestedQuote, err := tpms.Attested.Quote()

	if err != nil {
		return nil, err
	}

	if expectedPCRDigest != [32]byte(attestedQuote.PCRDigest.Buffer) {
		return nil, errors.New("plaintext TPMQuoteAttestation PCR values don't match the signed data")
	}

	pcrMap := make(map[uint32][]byte)
	for _, k := range orderedPCRIndices {
		kUint, err := safecast.ToUint32(k)

		if err != nil {
			return nil, err
		}

		pcrMap[kUint] = tpmQuoteProto.PCRValues.Values[kUint]
	}

	pcrValues := evidence.PCRValues{Values: pcrMap}

	return &pcrValues, nil
}
