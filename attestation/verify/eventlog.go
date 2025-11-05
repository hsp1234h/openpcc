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
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"

	pb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/cmdline"
	"github.com/openpcc/openpcc/transparency/statements"
	"google.golang.org/protobuf/proto"
)

const (
	KernelCmdlinePCRIndex = 8
	ModelHashPCRIndex     = 12
)

func EventLog(
	_ context.Context,
	_ *rsa.PublicKey,
	expectedPcr []register.MR,
	eventLogEvidence *ev.SignedEvidencePiece,
	imageManifest *statements.ImageManifest,
) error {
	rawEvents, secureBoot, err := getRawEventsAndSecureBootState(eventLogEvidence)
	if err != nil {
		return fmt.Errorf("failed to get raw events: %w", err)
	}

	if !secureBoot.Enabled {
		return errors.New("failed to verify event log: secure boot is not enabled")
	}

	err = verifyKernelCmdline(rawEvents, imageManifest)
	if err != nil {
		return fmt.Errorf("failed to verify kernel cmdline: %w", err)
	}

	for _, pcr := range expectedPcr {
		idx := pcr.Idx()
		if idx < 0 || idx > math.MaxUint32 {
			return fmt.Errorf("pcr index %d is out of range for uint32", idx)
		}
		if idx == ModelHashPCRIndex {
			// skip model hash PCR, since the event log only contains entries for
			// PCR extensions made by firmware
			continue
		}
		checksum := calculateEventLogChecksum(pcr.DgstAlg(), rawEvents, uint32(idx))
		if !bytes.Equal(checksum, pcr.Dgst()) {
			return fmt.Errorf("pcr %d does not match, expected %s, got %s", pcr.Idx(), hex.EncodeToString(pcr.Dgst()), hex.EncodeToString(checksum))
		}
	}

	return nil
}

func getRawEventsAndSecureBootState(evidencePiece *ev.SignedEvidencePiece) ([]*pb.Event, *pb.SecureBootState, error) {
	firmwareLogState := pb.FirmwareLogState{}

	err := proto.Unmarshal(evidencePiece.Data, &firmwareLogState)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal event log: %w", err)
	}

	rawEvents := firmwareLogState.GetRawEvents()
	secureBootState := firmwareLogState.GetSecureBoot()
	return rawEvents, secureBootState, nil
}

func verifyKernelCmdline(events []*pb.Event, imageManifest *statements.ImageManifest) error {
	if imageManifest.CustomData == nil {
		return errors.New("no custom data in image manifest")
	}

	kernelCmdlines := imageManifest.CustomData.KernelCmdlines
	if len(kernelCmdlines) == 0 {
		return errors.New("no kernel cmdlines found in image manifest")
	}

	verified := false
	for _, event := range events {
		pcrIndex := event.GetPcrIndex()
		eventData := event.GetData()
		// kernel cmdline is in PCR 8
		// https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/
		if pcrIndex != KernelCmdlinePCRIndex {
			continue
		}

		cmdlineStr := string(eventData)
		if !strings.HasPrefix(cmdlineStr, "kernel_cmdline:") {
			continue
		}

		cmdlineMap, err := cmdline.Parse(cmdlineStr)
		if err != nil {
			return fmt.Errorf("failed to parse kernel cmdline: %w", err)
		}

		confsecRoot, ok := cmdlineMap["confsec.root"]
		if !ok {
			return errors.New("confsec.root not found in kernel cmdline")
		}

		// All kernel cmdlines contain the same verity hash.
		// The first kernel cmdline is used during boot.
		// Remaining kernel cmdlines describe various boot modes like recovery
		if confsecRoot != kernelCmdlines[0].ConfsecRoot {
			return fmt.Errorf("confsec.root does not match image manifest, expected %s, got %s", kernelCmdlines[0].ConfsecRoot, cmdlineMap["confsec.root"])
		}
		verified = true
	}
	if !verified {
		return errors.New("confsec.root not found in kernel cmdline")
	}
	return nil
}

func calculateEventLogChecksum(hashAlg crypto.Hash, rawEvents []*pb.Event, registerIndex uint32) []byte {
	if !hashAlg.Available() {
		return []byte{}
	}

	checksum := make([]byte, 0)
	for _, event := range rawEvents {
		if event.GetPcrIndex() != registerIndex {
			continue
		}
		hasher := hashAlg.New()
		// Simulate PCR extend: PCR_new = SHA256(PCR_old || digest)
		// https://github.com/google/go-eventlog/tree/main?tab=readme-ov-file#measured-boot
		if len(checksum) != 0 {
			hasher.Write(checksum)
		} else {
			b := make([]byte, hasher.Size())
			hasher.Write(b)
		}
		hasher.Write(event.GetDigest())
		intermediateChecksum := hasher.Sum(nil)

		checksum = intermediateChecksum
	}
	return checksum
}
