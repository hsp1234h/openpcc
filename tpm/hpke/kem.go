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
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/google/go-tpm/tpm2"
	"golang.org/x/crypto/hkdf"
)

// tpmKEM is a Key Encapsulation Mechanism that uses private keys
// stored on the TPM. This KEM only decapsulates.
//
// The TPM assumes that ECC is used with P-256 curves. It will error
// when other keys are encountered.
//
// All crypto code is based on:
// https://github.com/cloudflare/circl/blob/91946a37b9b8da646abe6252153d918707cda136/hpke/shortkem.go
// https://github.com/cloudflare/circl/blob/934044546cbe134a0d45e019808ee414607346a1/hpke/kembase.go
type tpmKEM struct {
	base     hpke.KEM
	keyInfo  *ECDHZGenKeyInfo
	ecdhZGen ECDHZGenFunc
}

func (s *tpmKEM) decapsulate(
	pubKey kem.PublicKey,
	ct []byte) ([]byte, error) {
	dh := make([]byte, s.sizeDH())
	kemCtx, err := s.coreDecap(dh, pubKey, ct)
	if err != nil {
		return nil, err
	}

	return s.extractExpand(dh, kemCtx), nil
}

func (*tpmKEM) sizeDH() int {
	return (elliptic.P256().Params().BitSize + 7) / 8
}

func (s *tpmKEM) coreDecap(
	dh []byte,
	pubKey kem.PublicKey,
	ct []byte) ([]byte, error) {
	if len(ct) < 65 || ct[0] != 0x04 {
		return nil, errors.New("expected ct in uncompressed SEC1 format")
	}

	// get the ephemeral point
	pubPoint := tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: ct[1:33]},
		Y: tpm2.TPM2BECCParameter{Buffer: ct[33:]},
	}

	pubPoint2b := tpm2.New2B(pubPoint)

	// calculate dh on the tpm
	err := s.calcDH(dh, pubPoint2b)
	if err != nil {
		return nil, err
	}

	pkRm, err := pubKey.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(append([]byte{}, ct...), pkRm...), nil
}

func (s *tpmKEM) calcDH(
	dh []byte,
	pubPoint tpm2.TPM2BECCPoint) error {
	b, err := s.ecdhZGen(s.keyInfo, pubPoint)
	if err != nil {
		return fmt.Errorf("failed calculate dh using ecdhzgen: %w", err)
	}

	copy(dh[len(dh)-len(b):], b)
	return nil
}

func (s *tpmKEM) getSuiteID() [5]byte {
	sid := [5]byte{}
	sid[0], sid[1], sid[2] = 'K', 'E', 'M'
	binary.BigEndian.PutUint16(sid[3:5], uint16(s.base))
	return sid
}

func (s *tpmKEM) extractExpand(dh, kemCtx []byte) []byte {
	eaePkr := s.labeledExtract([]byte(""), []byte("eae_prk"), dh)
	return s.labeledExpand(
		eaePkr,
		[]byte("shared_secret"),
		kemCtx,
		uint16(hash.Size()), // #nosec
	)
}

func (s *tpmKEM) labeledExtract(salt, label, info []byte) []byte {
	suiteID := s.getSuiteID()
	labeledIKM := append(append(append(append(
		make([]byte, 0, len(versionLabel)+len(suiteID)+len(label)+len(info)),
		versionLabel...),
		suiteID[:]...),
		label...),
		info...)
	return hkdf.Extract(hash.New, labeledIKM, salt)
}

func (s *tpmKEM) labeledExpand(prk, label, info []byte, l uint16) []byte {
	suiteID := s.getSuiteID()
	labeledInfo := make(
		[]byte,
		2,
		2+len(versionLabel)+len(suiteID)+len(label)+len(info),
	)
	binary.BigEndian.PutUint16(labeledInfo[0:2], l)
	labeledInfo = append(append(append(append(labeledInfo,
		versionLabel...),
		suiteID[:]...),
		label...),
		info...)
	b := make([]byte, l)
	rd := hkdf.Expand(hash.New, prk, labeledInfo)
	if _, err := io.ReadFull(rd, b); err != nil {
		panic(err)
	}
	return b
}
