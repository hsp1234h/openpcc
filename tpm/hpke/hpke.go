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
	"crypto"
	"encoding/binary"
	"fmt"

	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/google/go-tpm/tpm2"
	cstpm "github.com/openpcc/openpcc/tpm"
)

var (
	// the hardcoded mode and suite we require for TPM based HPKE.
	modeID   = byte(0x00)
	tpmSuite = hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)

	versionLabel = "HPKE-v1"
	hash         = crypto.SHA256
)

func SuiteParams() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return tpmSuite.Params()
}

// Pub converts a TPM public key into one recognized by the circl/hpke package. Similar to internal/tpm.Pub, but
// for HPKE public keys.
func Pub(tpmpt *tpm2.TPMTPublic) (kem.PublicKey, error) {
	pubKey, err := cstpm.Pub(tpmpt)
	if err != nil {
		return nil, fmt.Errorf("failed to convert tpmpt to crypto public key: %w", err)
	}

	// TODO: check the hash algorithm when this is fixed:
	// https://github.com/google/go-tpm/issues/389
	eccPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ECDSA public key, got %T", pubKey)
	}

	if eccPubKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf(
			"requires ECC key with curve P256 and hash algorithm SHA256, got curve %v",
			eccPubKey.Curve.Params().Name,
		)
	}

	// Encode the point in SEC1 uncompressed point format.
	//
	// This looks like `0x04 + X + Y`
	// For the P256 curve, these X and Y should be in big endian format
	// padded to be 32 bytes.
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	// Note that the Bytes() function omits leading zeros, so we need to account for padding.
	copy(uncompressed[33-len(eccPubKey.X.Bytes()):33], eccPubKey.X.Bytes()) // Right-align X
	copy(uncompressed[65-len(eccPubKey.Y.Bytes()):65], eccPubKey.Y.Bytes()) // Right-align Y

	// Unmarshal to a binary public key we can use with the cloudflare ecosystem.
	kemID, _, _ := tpmSuite.Params()
	kemPubKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tpm key (x: %v y: %v) to kem.PublicKey: %w", eccPubKey.X.Bytes(), eccPubKey.Y.Bytes(), err)
	}

	return kemPubKey, nil
}

// Receiver performs hybrid public-key decryption using the provided
// TPM for cryptographic operations.
//
// Receiver is based on:
// https://github.com/cloudflare/circl/blob/91946a37b9b8da646abe6252153d918707cda136/hpke/hpke.go#L162
type Receiver struct {
	suite     hpke.Suite
	publicKey kem.PublicKey
	tpmKEM    *tpmKEM
	info      []byte
}

func NewReceiver(
	pubKey kem.PublicKey,
	info []byte,
	keyInfo *ECDHZGenKeyInfo,
	ecdhZGen ECDHZGenFunc) *Receiver {
	kemID, _, _ := tpmSuite.Params()

	return &Receiver{
		suite:     tpmSuite,
		publicKey: pubKey,
		tpmKEM: &tpmKEM{
			base:     kemID,
			keyInfo:  keyInfo,
			ecdhZGen: ecdhZGen,
		},
		info: info,
	}
}

func (r *Receiver) Setup(enc []byte) (hpke.Opener, error) {
	ss, err := r.tpmKEM.decapsulate(r.publicKey, enc)
	if err != nil {
		return nil, err
	}

	return r.keySchedule(ss, r.info)
}

// keySchedule is adapted from cloudflare/hpke.Receiver.keySchedule.
func (r *Receiver) keySchedule(ss, info []byte) (*openContext, error) {
	_, kdfID, aeadID := r.suite.Params()

	pskIDHash := r.labeledExtract(nil, []byte("psk_id_hash"), nil)
	infoHash := r.labeledExtract(nil, []byte("info_hash"), info)
	keySchCtx := append(append(
		[]byte{modeID},
		pskIDHash...),
		infoHash...)

	secret := r.labeledExtract(ss, []byte("secret"), nil)

	nk := uint16(aeadID.KeySize()) // #nosec
	key := r.labeledExpand(secret, []byte("key"), keySchCtx, nk)

	aead, err := aeadID.New(key)
	if err != nil {
		return nil, err
	}

	nn := uint16(aead.NonceSize()) // #nosec
	baseNonce := r.labeledExpand(secret, []byte("base_nonce"), keySchCtx, nn)
	exporterSecret := r.labeledExpand(
		secret,
		[]byte("exp"),
		keySchCtx,
		uint16(kdfID.ExtractSize()), // #nosec
	)

	return &openContext{
		r.suite,
		ss,
		secret,
		keySchCtx,
		exporterSecret,
		key,
		baseNonce,
		make([]byte, nn),
		aead,
		make([]byte, nn),
	}, nil
}

func (r *Receiver) labeledExtract(salt, label, ikm []byte) []byte {
	_, kdfID, _ := r.suite.Params()

	suiteID := r.getSuiteID()
	labeledIKM := append(append(append(append(
		make([]byte, 0, len(versionLabel)+len(suiteID)+len(label)+len(ikm)),
		versionLabel...),
		suiteID[:]...),
		label...),
		ikm...)
	return kdfID.Extract(labeledIKM, salt)
}

func (r *Receiver) labeledExpand(prk, label, info []byte, l uint16) []byte {
	_, kdfID, _ := r.suite.Params()

	suiteID := r.getSuiteID()
	labeledInfo := make([]byte,
		2, 2+len(versionLabel)+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo[0:2], l)
	labeledInfo = append(append(append(append(labeledInfo,
		versionLabel...),
		suiteID[:]...),
		label...),
		info...)
	return kdfID.Expand(prk, labeledInfo, uint(l))
}

func (r *Receiver) getSuiteID() [10]byte {
	kemID, kdfID, aeadID := r.suite.Params()

	id := [10]byte{}
	id[0], id[1], id[2], id[3] = 'H', 'P', 'K', 'E'
	binary.BigEndian.PutUint16(id[4:6], uint16(kemID))
	binary.BigEndian.PutUint16(id[6:8], uint16(kdfID))
	binary.BigEndian.PutUint16(id[8:10], uint16(aeadID))
	return id
}
