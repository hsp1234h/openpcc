// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security
//
// Licensed under the Confident Security Limited License, the
// terms and conditions of which are set forth in the "LICENSE"
// file included in the root directory of this code repository
// (the "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at
//
// license.confident.security/limited/v1
//
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

type BareMetalSEVSNPTEEAttestor struct {
	Nonce         []byte
	QuoteProvider sevsnpclient.SVSMQuoteProvider
	Getter        strust.HTTPSGetter
}

func NewBareMetalSEVSNPTEEAttestor(nonce []byte) (*BareMetalSEVSNPTEEAttestor, error) {
	quoteProvider, err := sevsnpclient.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create SEV-SNP quote provider: %w", err)
	}

	svsmQuoteProvider, ok := quoteProvider.(sevsnpclient.SVSMQuoteProvider)
	if !ok {
		return nil, errors.New("quote provider is not a SVSM quote provider")
	}

	return &BareMetalSEVSNPTEEAttestor{
		Nonce:         nonce,
		QuoteProvider: svsmQuoteProvider,
	}, nil
}

func NewBareMetalSEVSNPTEEAttestorWithGetter(nonce []byte, getter strust.HTTPSGetter) (*BareMetalSEVSNPTEEAttestor, error) {
	quoteProvider, err := sevsnpclient.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create SEV-SNP quote provider: %w", err)
	}

	svsmQuoteProvider, ok := quoteProvider.(sevsnpclient.SVSMQuoteProvider)
	if !ok {
		return nil, errors.New("quote provider is not a SVSM quote provider")
	}

	return &BareMetalSEVSNPTEEAttestor{
		Nonce:         nonce,
		QuoteProvider: svsmQuoteProvider,
		Getter:        getter,
	}, nil
}

func (*BareMetalSEVSNPTEEAttestor) Name() string {
	return "BareMetalSEVSNPTEEAttestor"
}

// Returns a SignedEvidencePiece containing a SEV-SNP attestation report,
// (documentation https://www.amd.com/system/files/TechDocs/56860.pdf)
// certificate chain for the VCEK, and the manifest returned by a SVSM attest services request
// Format of Data:
// [64]byte ReportData (snpNonce) | []byte Attestation (protobuf)
func (a *BareMetalSEVSNPTEEAttestor) CreateSignedEvidence(ctx context.Context) (*evidence.SignedEvidencePiece, error) {
	isSupported := a.QuoteProvider.IsSupported()
	if !isSupported {
		return nil, errors.New("SEVSNP or configfs is not supported on this platform")
	}

	var snpNonce [sabi.ReportDataSize]byte
	if len(a.Nonce) != sabi.ReportDataSize {
		return nil, fmt.Errorf("the TEENonce size is %d. SEV-SNP device requires 64", len(a.Nonce))
	}

	copy(snpNonce[:], a.Nonce)

	raw, err := a.QuoteProvider.GetRawQuoteSVSM(snpNonce)
	if err != nil {
		return nil, err
	}

	attestation, err := sabi.ReportCertsAndManifestToProto(raw)
	if err != nil {
		return nil, err
	}

	// calling this will fill in the certificate chain for the VCEK
	err = sv.GetAttestationWithCertsContext(
		ctx,
		attestation,
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
		Data:      append(snpNonce[:], attestationBytes...),
		Signature: raw,
		Type:      evidence.SevSnpExtendedReport,
	}, nil
}
