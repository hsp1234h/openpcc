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
	"crypto"
	"testing"

	pb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/transparency/statements"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestEventLog_Success(t *testing.T) {
	imageManifest := &statements.ImageManifest{
		CustomData: &statements.BuildCustomData{
			KernelCmdlines: []statements.KernelCmdline{
				{
					ConfsecRoot: "test-root-hash",
				},
			},
		},
	}

	events := []*pb.Event{
		{
			PcrIndex: KernelCmdlinePCRIndex,
			Data:     []byte("kernel_cmdline: ro quiet splash confsec.root=test-root-hash"),
			Digest:   []byte("digest1"),
		},
	}

	evidencePiece := createTestEvidencePiece(t, events, true)

	mrs := []register.MR{
		register.PCR{
			Index:     KernelCmdlinePCRIndex,
			DigestAlg: crypto.SHA256,
			Digest:    calculateEventLogChecksum(crypto.SHA256, events, KernelCmdlinePCRIndex),
		},
	}

	err := EventLog(t.Context(), nil, mrs, evidencePiece, imageManifest)
	require.NoError(t, err)
}

func TestEventLog_KernelCmdlineNotFound(t *testing.T) {
	imageManifest := &statements.ImageManifest{
		CustomData: &statements.BuildCustomData{
			KernelCmdlines: []statements.KernelCmdline{
				{
					ConfsecRoot: "test-root-hash",
				},
			},
		},
	}

	events := []*pb.Event{
		{
			PcrIndex: KernelCmdlinePCRIndex,
			Data:     []byte("ro quiet splash"),
			Digest:   []byte("digest1"),
		},
	}

	evidencePiece := createTestEvidencePiece(t, events, true)
	mrs := []register.MR{}

	err := EventLog(t.Context(), nil, mrs, evidencePiece, imageManifest)
	require.ErrorContains(t, err, "confsec.root not found in kernel cmdline")
}

func TestEventLog_MismatchedConfsecRoot(t *testing.T) {
	imageManifest := &statements.ImageManifest{
		CustomData: &statements.BuildCustomData{
			KernelCmdlines: []statements.KernelCmdline{
				{
					ConfsecRoot: "expected-hash",
				},
			},
		},
	}

	events := []*pb.Event{
		{
			PcrIndex: KernelCmdlinePCRIndex,
			Data:     []byte("kernel_cmdline: ro quiet splash confsec.root=different-hash"),
			Digest:   []byte("digest1"),
		},
	}

	evidencePiece := createTestEvidencePiece(t, events, true)
	mrs := []register.MR{}

	err := EventLog(t.Context(), nil, mrs, evidencePiece, imageManifest)
	require.ErrorContains(t, err, "confsec.root does not match image manifest")
}

func TestEventLog_NoCustomData(t *testing.T) {
	imageManifest := &statements.ImageManifest{
		CustomData: nil,
	}

	events := []*pb.Event{}
	evidencePiece := createTestEvidencePiece(t, events, true)
	mrs := []register.MR{}

	err := EventLog(t.Context(), nil, mrs, evidencePiece, imageManifest)
	require.ErrorContains(t, err, "no custom data in image manifest")
}

func TestEventLog_NoKernelCmdlines(t *testing.T) {
	imageManifest := &statements.ImageManifest{
		CustomData: &statements.BuildCustomData{
			KernelCmdlines: []statements.KernelCmdline{},
		},
	}

	events := []*pb.Event{}
	evidencePiece := createTestEvidencePiece(t, events, true)
	mrs := []register.MR{}

	err := EventLog(t.Context(), nil, mrs, evidencePiece, imageManifest)
	require.ErrorContains(t, err, "no kernel cmdlines found in image manifest")
}

func TestEventLog_PCRMismatch(t *testing.T) {
	imageManifest := &statements.ImageManifest{
		CustomData: &statements.BuildCustomData{
			KernelCmdlines: []statements.KernelCmdline{
				{
					ConfsecRoot: "test-root-hash",
				},
			},
		},
	}

	events := []*pb.Event{
		{
			PcrIndex: KernelCmdlinePCRIndex,
			Data:     []byte("kernel_cmdline: ro quiet splash confsec.root=test-root-hash"),
			Digest:   []byte("digest1"),
		},
	}

	evidencePiece := createTestEvidencePiece(t, events, true)

	mrs := []register.MR{
		register.PCR{
			Index:     KernelCmdlinePCRIndex,
			DigestAlg: crypto.SHA256,
			Digest:    []byte("wrong-checksum"),
		},
	}

	err := EventLog(t.Context(), nil, mrs, evidencePiece, imageManifest)
	require.ErrorContains(t, err, "pcr 8 does not match")
}

func TestEventLog_SecureBootDisabled(t *testing.T) {
	imageManifest := &statements.ImageManifest{
		CustomData: &statements.BuildCustomData{
			KernelCmdlines: []statements.KernelCmdline{
				{
					ConfsecRoot: "test-root-hash",
				},
			},
		},
	}

	events := []*pb.Event{
		{
			PcrIndex: KernelCmdlinePCRIndex,
			Data:     []byte("kernel_cmdline: ro quiet splash confsec.root=test-root-hash"),
			Digest:   []byte("digest1"),
		},
	}

	evidencePiece := createTestEvidencePiece(t, events, false)

	mrs := []register.MR{}

	err := EventLog(t.Context(), nil, mrs, evidencePiece, imageManifest)
	require.ErrorContains(t, err, "secure boot is not enabled")
}

func createTestEvidencePiece(t *testing.T, events []*pb.Event, secureBootEnabled bool) *ev.SignedEvidencePiece {
	firmwareLogState := &pb.FirmwareLogState{
		RawEvents: events,
		SecureBoot: &pb.SecureBootState{
			Enabled: secureBootEnabled,
		},
	}

	data, err := proto.Marshal(firmwareLogState)
	require.NoError(t, err)

	return &ev.SignedEvidencePiece{
		Data: data,
	}
}
