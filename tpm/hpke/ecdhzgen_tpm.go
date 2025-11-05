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

package hpke

import (
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/hpke"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// ECDHZGenKeyInfo contains the key information required to call ECDHZGen that can't be derived
// from the kem.PublicKey provided to the Receiver.
type ECDHZGenKeyInfo struct {
	PrivKeyHandle tpmutil.Handle
	PublicName    tpm2.TPM2BName
}

// ECDHZGenFunc is the function type invoked by the Receiver when it needs to call ECDHZgen. This is not hardcoded,
// so that the caller can decide how it is invoked and linked to a TPM connection or session.
type ECDHZGenFunc func(keyInfo *ECDHZGenKeyInfo, pubPoint tpm2.TPM2BECCPoint) ([]byte, error)

func ECDHZGen(tpm transport.TPM, sess tpm2.Session, keyInfo *ECDHZGenKeyInfo, pubPoint tpm2.TPM2BECCPoint) ([]byte, error) {
	// Calculate Z based on TPM priv * SW pub
	ecdhzRequest := tpm2.ECDHZGen{
		KeyHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(keyInfo.PrivKeyHandle),
			Name:   keyInfo.PublicName,
			Auth:   sess,
		},
		InPoint: pubPoint,
	}
	ecdhzResponse, err := ecdhzRequest.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared point: %w", err)
	}

	zPoint, err := ecdhzResponse.OutPoint.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to umarshal shared point: %w", err)
	}

	b := zPoint.X.Buffer

	xInteger := new(big.Int).SetBytes(b)

	if xInteger.Sign() == 0 {
		return nil, hpke.ErrInvalidKEMSharedSecret
	}

	return b, nil
}
