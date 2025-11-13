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
package attest

import (
	"context"
	"crypto"
	"io"

	"github.com/openpcc/openpcc/attestation/evidence"

	"github.com/google/go-eventlog/extract"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
	"google.golang.org/protobuf/proto"
)

// See https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf#page=103
type EventLogAttestor struct {
	LogReader         io.Reader
	ExpectedPCRValues []register.MR
}

func NewEventLogAttestor(logReader io.Reader, expectedPCRValues []register.MR) (*EventLogAttestor, error) {
	return &EventLogAttestor{
		LogReader:         logReader,
		ExpectedPCRValues: expectedPCRValues,
	}, nil
}

func (*EventLogAttestor) Name() string {
	return "EventLogAttestor"
}

func (a *EventLogAttestor) CreateSignedEvidence(_ context.Context) (*evidence.SignedEvidencePiece, error) {
	rawEventLog, err := io.ReadAll(a.LogReader)
	if err != nil {
		return nil, err
	}

	eventLog, err := tcg.ParseAndReplay(
		rawEventLog,
		a.ExpectedPCRValues,
		tcg.ParseOpts{},
	)
	if err != nil {
		return nil, err
	}

	flg, err := extract.FirmwareLogState(
		eventLog,
		crypto.SHA256,
		extract.TPMRegisterConfig,
		extract.Opts{
			Loader: extract.GRUB,
		},
	)
	if err != nil {
		return nil, err
	}
	msg, err := proto.Marshal(flg)
	if err != nil {
		return nil, err
	}

	return &evidence.SignedEvidencePiece{
		Type:      evidence.EventLog,
		Data:      msg,
		Signature: []byte{},
	}, nil
}
