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
package attest_test

import (
	"encoding/binary"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/openpcc/openpcc/attestation/attest"
)

/**
 * This file contains a TPM wrapper for testing purposes.
 *
 * It intercepts NVRead commands and returns the provided
 * response bytes.
 *
 * All other commands other than NVRead and NVReadPublic are passed to the real TPM.
 *
 * This is required because cloud providers store values in their vTPM NV space that are larger than
 * the TPM simulator allows, such as TD reports and certificates.
 */
type TPMNVWrapper struct {
	realtpm       transport.TPM
	responseBytes []byte
}

func (m *TPMNVWrapper) Send(input []byte) ([]byte, error) {
	cmdHeader, err := tpm2.Unmarshal[tpm2.TPMCmdHeader](input)
	if err != nil {
		return nil, err
	}

	//nolint:exhaustive
	switch cmdHeader.CommandCode {
	case tpm2.TPMCCNVRead:
		inputLen := len(input)
		readSize := binary.BigEndian.Uint16(input[inputLen-4 : inputLen-2])
		readOffset := binary.BigEndian.Uint16(input[inputLen-2:])
		mockReadSuccess := []byte{}

		content := tpm2.TPM2BMaxNVBuffer{
			Buffer: m.responseBytes[readOffset : readOffset+readSize],
		}

		contentBytes := tpm2.Marshal(content)

		lenContent := uint32(len(contentBytes))

		header := tpm2.TPMRspHeader{
			Tag:          tpm2.TPMSTSessions,
			Length:       lenContent,
			ResponseCode: tpm2.TPMRCSuccess,
		}
		headerBytes := tpm2.Marshal(header)

		authResponse := tpm2.TPMSAuthResponse{
			Nonce: tpm2.TPM2BNonce{
				Buffer: []byte{},
			},
			Authorization: tpm2.TPM2BData{
				Buffer: []byte{},
			},
			Attributes: tpm2.TPMASession{
				ContinueSession: true,
			},
		}

		authResponseBytes := tpm2.Marshal(authResponse)

		mockReadSuccess = append(mockReadSuccess, headerBytes...)
		contentWithHeaderLength := make([]byte, 4)

		binary.BigEndian.PutUint32(contentWithHeaderLength, uint32(len(contentBytes)))
		mockReadSuccess = append(mockReadSuccess, contentWithHeaderLength...)
		mockReadSuccess = append(mockReadSuccess, contentBytes...)
		mockReadSuccess = append(mockReadSuccess, authResponseBytes...)

		return mockReadSuccess, nil
	case tpm2.TPMCCNVReadPublic:
		mockReadPublicSuccess := []byte{}

		content := tpm2.TPMSNVPublic{
			NVIndex: tpm2.TPMHandle(attest.AzureTDReportReadNVIndex),
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				OwnerRead: true,
			},
			AuthPolicy: tpm2.TPM2BDigest{
				Buffer: []byte{},
			},
			DataSize: uint16(len(m.responseBytes)),
		}

		content2B := tpm2.New2B[tpm2.TPMSNVPublic](content)

		contentBytes := tpm2.Marshal(content2B)

		name := tpm2.Marshal(tpm2.HandleName(tpm2.TPMHandle(attest.AzureTDReportReadNVIndex)))
		lenContent := uint32(len(contentBytes) + len(name))

		header := tpm2.TPMRspHeader{
			Tag:          tpm2.TPMSTNoSessions,
			Length:       lenContent,
			ResponseCode: tpm2.TPMRCSuccess,
		}
		headerBytes := tpm2.Marshal(header)

		mockReadPublicSuccess = append(mockReadPublicSuccess, headerBytes...)
		mockReadPublicSuccess = append(mockReadPublicSuccess, contentBytes...)
		mockReadPublicSuccess = append(mockReadPublicSuccess, name...)
		return mockReadPublicSuccess, nil
	default:
		return m.realtpm.Send(input)
	}
}
