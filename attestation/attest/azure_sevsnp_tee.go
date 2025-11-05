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
	"fmt"
	"time"

	sabi "github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	sv "github.com/google/go-sev-guest/verify"
	strust "github.com/google/go-sev-guest/verify/trust"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/openpcc/openpcc/attestation/evidence"
	cstpm "github.com/openpcc/openpcc/tpm"
	"google.golang.org/protobuf/proto"
)

const (
	AzureTDReportReadNVIndex  uint32 = 0x1400001
	AzureTDReportWriteNVIndex uint32 = 0x1400002
	AzureSEVSNPReportSize     uint32 = 1184
	AzureSEVSNPReportOffset   uint32 = 32
)

type AzureSEVSNPTEEAttestor struct {
	tpm     transport.TPM
	Nonce   []byte
	Product *spb.SevProduct
	Getter  strust.HTTPSGetter
}

func NewAzureSEVSNPTEEAttestor(tpm transport.TPM, nonce []byte) *AzureSEVSNPTEEAttestor {
	return &AzureSEVSNPTEEAttestor{
		tpm:   tpm,
		Nonce: nonce,
	}
}

func NewAzureSEVSNPTEEAttestorWithGetter(tpm transport.TPM, nonce []byte, getter strust.HTTPSGetter) *AzureSEVSNPTEEAttestor {
	return &AzureSEVSNPTEEAttestor{
		tpm:    tpm,
		Nonce:  nonce,
		Getter: getter,
	}
}

func (*AzureSEVSNPTEEAttestor) Name() string {
	return "AzureSEVSNPTEEAttestor"
}

func (a *AzureSEVSNPTEEAttestor) CreateSignedEvidence(ctx context.Context) (*evidence.SignedEvidencePiece, error) {
	emptyNonce := make([]byte, sabi.ReportDataSize)

	err := cstpm.WriteToNVRamNoAuth(
		a.tpm,
		tpmutil.Handle(AzureTDReportWriteNVIndex),
		emptyNonce)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to write empty nonce to NV index (%x): %w",
			AzureTDReportWriteNVIndex,
			err)
	}

	raw, err := cstpm.NVReadEXNoAuthorization(a.tpm, tpmutil.Handle(AzureTDReportReadNVIndex))
	if err != nil {
		return nil, fmt.Errorf("failed to read TD report from NV index (%x): %w", AzureTDReportReadNVIndex, err)
	}

	report, err := sabi.ReportToProto(raw[AzureSEVSNPReportOffset:(AzureSEVSNPReportOffset + AzureSEVSNPReportSize)])

	if err != nil {
		return nil, err
	}

	attestation, err := sv.GetAttestationFromReportContext(
		ctx,
		report,
		&sv.Options{
			Getter:           a.Getter,
			Now:              time.Now(),
			CheckRevocations: true,
		},
	)
	if err != nil {
		return nil, err
	}

	attestationBytes, err := proto.Marshal(attestation)
	if err != nil {
		return nil, err
	}

	return &evidence.SignedEvidencePiece{
		Data:      attestationBytes,
		Signature: raw,
		Type:      evidence.SevSnpReport,
	}, nil
}
