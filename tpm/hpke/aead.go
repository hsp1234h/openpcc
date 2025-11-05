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
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/hpke"
)

// openContext is based on:
// https://github.com/cloudflare/circl/blob/91946a37b9b8da646abe6252153d918707cda136/hpke/aead.go
type openContext struct {
	// Serialized parameters
	suite              hpke.Suite
	sharedSecret       []byte
	secret             []byte
	keyScheduleContext []byte
	exporterSecret     []byte
	key                []byte
	baseNonce          []byte
	sequenceNumber     []byte

	// Operational parameters
	cipher.AEAD
	nonce []byte
}

// Export takes a context string exporterContext and a desired length (in
// bytes), and produces a secret derived from the internal exporter secret
// using the corresponding KDF Expand function. It panics if length is
// greater than 255*N bytes, where N is the size (in bytes) of the KDF's
// output.
func (c *openContext) Export(exporterContext []byte, length uint) []byte {
	_, kdfID, _ := c.suite.Params()

	maxLength := uint(255 * kdfID.ExtractSize()) // #nosec
	if length > maxLength {
		panic(fmt.Errorf("output length must be lesser than %v bytes", maxLength))
	}
	return c.labeledExpand(c.exporterSecret, []byte("sec"),
		exporterContext, uint16(length)) // #nosec
}

func (c *openContext) Suite() hpke.Suite {
	return c.suite
}

func (c *openContext) calcNonce() []byte {
	for i := range c.baseNonce {
		c.nonce[i] = c.baseNonce[i] ^ c.sequenceNumber[i]
	}
	return c.nonce
}

func (c *openContext) increment() error {
	// tests whether the sequence number is all-ones, which prevents an
	// overflow after the increment.
	allOnes := byte(0xFF)
	for i := range c.sequenceNumber {
		allOnes &= c.sequenceNumber[i]
	}
	if allOnes == byte(0xFF) {
		return hpke.ErrAEADSeqOverflows
	}

	// performs an increment by 1 and verifies whether the sequence overflows.
	carry := uint(1)
	for i := len(c.sequenceNumber) - 1; i >= 0; i-- {
		sum := uint(c.sequenceNumber[i]) + carry
		carry = sum >> 8
		c.sequenceNumber[i] = byte(sum & 0xFF)
	}
	if carry != 0 {
		return hpke.ErrAEADSeqOverflows
	}
	return nil
}

func (c *openContext) Open(ct, aad []byte) ([]byte, error) {
	pt, err := c.AEAD.Open(nil, c.calcNonce(), ct, aad)
	if err != nil {
		return nil, err
	}
	err = c.increment()
	if err != nil {
		for i := range pt {
			pt[i] = 0
		}
		return nil, err
	}
	return pt, nil
}

func (*openContext) MarshalBinary() ([]byte, error) {
	// not implemented but required to implement the hpke.Opener interface.
	return nil, errors.New("not implemented")
}

func (c *openContext) labeledExpand(prk, label, info []byte, l uint16) []byte {
	_, kdfID, _ := c.suite.Params()
	suiteID := c.getSuiteID()
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

func (c *openContext) getSuiteID() [10]byte {
	id := [10]byte{}
	kemID, kdfID, aeadID := c.suite.Params()
	id[0], id[1], id[2], id[3] = 'H', 'P', 'K', 'E'
	binary.BigEndian.PutUint16(id[4:6], uint16(kemID))
	binary.BigEndian.PutUint16(id[6:8], uint16(kdfID))
	binary.BigEndian.PutUint16(id[8:10], uint16(aeadID))
	return id
}
