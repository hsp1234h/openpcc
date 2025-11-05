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

	"github.com/google/go-tdx-guest/abi"
	tdxclient "github.com/google/go-tdx-guest/client"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxverify "github.com/google/go-tdx-guest/verify"
	"github.com/openpcc/openpcc/attestation/evidence"
)

type TDXTEEAttestor struct {
	Nonce         []byte
	QuoteProvider tdxclient.QuoteProvider
}

func NewTDXTEEAttestor(nonce []byte) (*TDXTEEAttestor, error) {
	quoteProvider, err := tdxclient.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create SEV-SNP quote provider: %w", err)
	}

	return &TDXTEEAttestor{
		Nonce:         nonce,
		QuoteProvider: quoteProvider,
	}, nil
}

func (*TDXTEEAttestor) Name() string {
	return "TDXTEEAttestor"
}

func (a *TDXTEEAttestor) CreateSignedEvidence(_ context.Context) (*evidence.SignedEvidencePiece, error) {
	isSupportedErr := a.QuoteProvider.IsSupported()
	if isSupportedErr != nil {
		return nil, isSupportedErr
	}

	var tdxNonce [abi.ReportDataSize]byte
	if len(a.Nonce) != 64 {
		return nil, fmt.Errorf("the TEENonce size is %d. TDX device requires 64", len(a.Nonce))
	}

	copy(tdxNonce[:], a.Nonce)

	rawQuoteBytes, err := a.QuoteProvider.GetRawQuote(tdxNonce)
	if err != nil {
		return nil, err
	}

	report, err := abi.QuoteToProto(rawQuoteBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse attestation report: %w", err)
	}

	chain, err := ExtractChainFromQuote(report)

	signatureBytes := chain.RootCertificate.Signature

	if err != nil {
		return nil, fmt.Errorf("could not interpret report: %w", err)
	}

	return &evidence.SignedEvidencePiece{
		Type:      evidence.TdxReport,
		Data:      rawQuoteBytes,
		Signature: signatureBytes,
	}, nil
}

func ExtractChainFromQuote(quote any) (*tdxverify.PCKCertificateChain, error) {
	switch q := quote.(type) {
	case *tdxpb.QuoteV4:
		return ExtractChainFromQuoteV4(q)
	default:
		return nil, fmt.Errorf("unsupported quote type: %T", quote)
	}
}
