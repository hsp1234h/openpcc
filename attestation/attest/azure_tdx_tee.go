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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/openpcc/openpcc/attestation/evidence"
	cstpm "github.com/openpcc/openpcc/tpm"
	"github.com/pkg/errors"
)

const (
	AzureTDXReportSize   uint32 = 1024
	AzureTDXReportOffset uint32 = 32
	// revive:disable:unsecure-url-scheme
	AzureTDXReportURL string = "http://169.254.169.254"
)

type MetadataQuoteService interface {
	GetQuote(ctx context.Context, report []byte) ([]byte, error)
}

type HTTPMetadataQuoteService struct{}

// Get uses http.Get to return the HTTPS response body as a byte array.
func (*HTTPMetadataQuoteService) GetQuote(ctx context.Context, report []byte) ([]byte, error) {
	quoteReq := struct {
		Report string `json:"report"`
	}{
		Report: base64.URLEncoding.EncodeToString(report),
	}

	requestBody, err := json.Marshal(quoteReq)
	if err != nil {
		return nil, err
	}

	// nosemgrep
	request, err := http.NewRequest(http.MethodPost, AzureTDXReportURL+"/acc/tdquote", bytes.NewReader(requestBody))

	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/json")
	request = request.WithContext(ctx)

	httpClient := http.DefaultClient
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, errors.Wrapf(err, "Request to %q failed", request.URL)
	}

	defer func() {
		err := response.Body.Close()
		slog.Warn("error closing http body", "error", err)
	}()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Errorf("Failed to read response body: %s", err)
	}

	if response.StatusCode != http.StatusOK || response.ContentLength == 0 {
		return nil, errors.Errorf("Request to %q failed: StatusCode = %d, Body = %s", request.URL, response.StatusCode, string(body))
	}

	quoteResponse := struct {
		Quote string `json:"quote"`
	}{}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&quoteResponse)
	if err != nil {
		return nil, errors.Wrap(err, "Error unmarshalling quote response from azure")
	}

	tdxQuote, err := base64.RawURLEncoding.DecodeString(quoteResponse.Quote)
	if err != nil {
		return nil, errors.Wrap(err, "Error decoding quote from azure")
	}

	return tdxQuote, nil
}

type AzureTDXTEEAttestor struct {
	tpm          transport.TPM
	Nonce        []byte
	QuoteService MetadataQuoteService
}

func NewAzureTDXTEEAttestor(tpm transport.TPM, nonce []byte) *AzureTDXTEEAttestor {
	return &AzureTDXTEEAttestor{
		tpm:          tpm,
		Nonce:        nonce,
		QuoteService: &HTTPMetadataQuoteService{},
	}
}

func NewAzureTDXTEEAttestorWithQuoteService(tpm transport.TPM, nonce []byte, quoteService MetadataQuoteService) *AzureTDXTEEAttestor {
	return &AzureTDXTEEAttestor{
		tpm:          tpm,
		Nonce:        nonce,
		QuoteService: quoteService,
	}
}

func (*AzureTDXTEEAttestor) Name() string {
	return "AzureTDXTEEAttestor"
}

func (a *AzureTDXTEEAttestor) CreateSignedEvidence(ctx context.Context) (*evidence.SignedEvidencePiece, error) {
	err := cstpm.WriteToNVRamNoAuth(
		a.tpm,
		tpmutil.Handle(AzureTDReportWriteNVIndex),
		a.Nonce)

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

	rawQuoteBytes, err := a.QuoteService.GetQuote(
		ctx,
		raw[AzureTDXReportOffset:(AzureTDXReportOffset+AzureTDXReportSize)],
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get tdx report: %w", err)
	}

	report, err := abi.QuoteToProto(rawQuoteBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse attestation report: %w", err)
	}

	chain, err := ExtractChainFromQuote(report)

	if err != nil {
		return nil, fmt.Errorf("failed to extract chain: %w", err)
	}

	signatureBytes := chain.RootCertificate.Signature

	return &evidence.SignedEvidencePiece{
		Type:      evidence.TdxReport,
		Data:      rawQuoteBytes,
		Signature: signatureBytes,
	}, nil
}
