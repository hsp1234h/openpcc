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

package credentialing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/openpcc/openpcc/gen/protos"
	"google.golang.org/protobuf/proto"
)

const PrefixLen = 4

// Credentials represents a set of permissions for a given user
type Credentials struct {
	Models []string
}

func (c *Credentials) MarshalProto() (*protos.Credentials, error) {
	modelsBytearray, err := encodeStrings(c.Models)
	if err != nil {
		return nil, err
	}
	return protos.Credentials_builder{
		Models: modelsBytearray,
	}.Build(), nil
}

func (c *Credentials) UnmarshalProto(creds *protos.Credentials) error {
	modelsBytearray := creds.GetModels()
	models, err := decodeStrings(modelsBytearray)
	if err != nil {
		return err
	}
	c.Models = models
	return nil
}

func (c *Credentials) MarshalBinary() ([]byte, error) {
	creds, err := c.MarshalProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(creds)
}

func isValidASCII(str string) bool {
	for _, c := range str {
		if c >= 127 || c < 32 {
			return false
		}
	}
	return true
}

func encodeStrings(strs []string) ([]byte, error) {
	stringsBuf := new(bytes.Buffer)
	encodingSize := 0

	sort.Strings(strs)
	for _, str := range strs {
		bytesWritten, err := encodeString(stringsBuf, str)
		if err != nil {
			return nil, err
		}
		encodingSize += bytesWritten
	}
	return stringsBuf.Bytes(), nil
}

func encodeString(buf *bytes.Buffer, str string) (int, error) {
	if !isValidASCII(str) {
		return -1, errors.New("unsupported string: contains non-ascii characters")
	}
	if len(str) == 0 {
		return -1, errors.New("failed to encode string: length must be greater than 0")
	} else if len(str) > math.MaxUint32 {
		return -1, errors.New("failed to encode string: exceeded maximum length")
	}

	// write string prefix, which is 4 bytes long and contains the value of len(str)
	//nolint:gosec
	strLength := uint32(len(str))
	err := binary.Write(buf, binary.LittleEndian, strLength)
	if err != nil {
		return -1, fmt.Errorf("failed to encode string: %w", err)
	}

	bytesWritten, err := buf.WriteString(str)
	if err != nil {
		return -1, fmt.Errorf("failed to encode string: %w", err)
	}
	if bytesWritten != len(str) {
		return -1, errors.New("failed to encode string. unexpected number of bytes written")
	}
	return bytesWritten + PrefixLen, nil
}

func decodeStrings(strList []byte) ([]string, error) {
	buf := bytes.NewBuffer(strList)
	strs := []string{}

	for buf.Len() > 0 {
		str, err := decodeString(buf)
		if err != nil {
			return nil, err
		}
		strs = append(strs, str)
	}
	if !sort.StringsAreSorted(strs) {
		return nil, errors.New("failed to decode strings list. strings are not sorted")
	}
	return strs, nil
}

func decodeString(buf *bytes.Buffer) (string, error) {
	var prefix uint32
	err := binary.Read(buf, binary.LittleEndian, &prefix)
	if err != nil {
		return "", fmt.Errorf("failed to decode string length: %w", err)
	}

	if prefix == 0 {
		return "", errors.New("failed to decode string, length must be greater than 0")
	}

	strLen := prefix
	strBytes := make([]byte, strLen)
	bytesRead, err := buf.Read(strBytes)
	if err != nil {
		return "", fmt.Errorf("failed to decode string: %w", err)
	}
	if bytesRead != int(strLen) {
		return "", errors.New("failed to decode string. unexpected number of bytes read")
	}

	str := string(strBytes)
	if !isValidASCII(str) {
		return "", errors.New("failed to decode string: contains non-ascii characters")
	}

	return str, nil
}
