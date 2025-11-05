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

package inttest

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/confidentsecurity/twoway"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	"github.com/stretchr/testify/require"
)

func NewComputeNodeReceiver(t *testing.T) (*twoway.MultiRequestReceiver, ev.ComputeData) {
	t.Helper()

	kemID := hpke.KEM_P256_HKDF_SHA256
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AES128GCM

	// generate key pair
	pubKey, privKey, err := kemID.Scheme().GenerateKeyPair()
	require.NoError(t, err)

	pubKeyB, err := pubKey.MarshalBinary()
	require.NoError(t, err)

	rcv, err := twoway.NewMultiRequestReceiver(hpke.NewSuite(kemID, kdfID, aeadID), 0, privKey, rand.Reader)
	require.NoError(t, err)

	return rcv, ev.ComputeData{
		KEM:       kemID,
		KDF:       kdfID,
		AEAD:      aeadID,
		PublicKey: pubKeyB,
	}
}

func NewClientSender(t *testing.T, computeData ev.ComputeData) *twoway.MultiRequestSender {
	t.Helper()

	suite := hpke.NewSuite(computeData.KEM, computeData.KDF, computeData.AEAD)
	return twoway.NewMultiRequestSender(suite, rand.Reader)
}
