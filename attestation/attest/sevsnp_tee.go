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
	"errors"
	"fmt"
	"time"

	sabi "github.com/google/go-sev-guest/abi"
	sevsnpclient "github.com/google/go-sev-guest/client"
	sv "github.com/google/go-sev-guest/verify"
	strust "github.com/google/go-sev-guest/verify/trust"
	"github.com/openpcc/openpcc/attestation/evidence"
	"google.golang.org/protobuf/proto"
)

type SEVSNPTEEAttestor struct {
	Nonce         []byte
	QuoteProvider sevsnpclient.QuoteProvider
	Getter        strust.HTTPSGetter
}

func NewSEVSNPTEEAttestor(nonce []byte) (*SEVSNPTEEAttestor, error) {
	quoteProvider, err := sevsnpclient.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create SEV-SNP quote provider: %w", err)
	}

	return &SEVSNPTEEAttestor{
		Nonce:         nonce,
		QuoteProvider: quoteProvider,
	}, nil
}

func NewSEVSNPTEEAttestorWithGetter(nonce []byte, getter strust.HTTPSGetter) (*SEVSNPTEEAttestor, error) {
	quoteProvider, err := sevsnpclient.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create SEV-SNP quote provider: %w", err)
	}

	return &SEVSNPTEEAttestor{
		Nonce:         nonce,
		QuoteProvider: quoteProvider,
		Getter:        getter,
	}, nil
}

func (*SEVSNPTEEAttestor) Name() string {
	return "SEVSNPTEEAttestor"
}

func (a *SEVSNPTEEAttestor) CreateSignedEvidence(ctx context.Context) (*evidence.SignedEvidencePiece, error) {
	isSupported := a.QuoteProvider.IsSupported()
	if !isSupported {
		return nil, errors.New("SEVSNP or configfs is not supported on this platform")
	}

	var snpNonce [sabi.ReportDataSize]byte
	if len(a.Nonce) != sabi.ReportDataSize {
		return nil, fmt.Errorf("the TEENonce size is %d. SEV-SNP device requires 64", len(a.Nonce))
	}

	copy(snpNonce[:], a.Nonce)

	raw, err := a.QuoteProvider.GetRawQuote(snpNonce)
	if err != nil {
		return nil, err
	}

	report, err := sabi.ReportToProto(raw)
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
