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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"

	"github.com/google/go-tdx-guest/pcs"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
	"github.com/openpcc/openpcc/attestation/evidence"
)

var (
	platformIssuer    = "Intel SGX PCK Platform CA"
	platformIssuerID  = "platform"
	processorIssuer   = "Intel SGX PCK Processor CA"
	processorIssuerID = "processor"
	certificateType   = "CERTIFICATE"
)

type TDXCollateralAttestor struct {
	Getter         trust.HTTPSGetter
	PCKCertificate *x509.Certificate
}

func NewTDXCollateralAttestor(getter trust.HTTPSGetter, pckCert *x509.Certificate) (*TDXCollateralAttestor, error) {
	return &TDXCollateralAttestor{
		Getter:         getter,
		PCKCertificate: pckCert,
	}, nil
}

func (*TDXCollateralAttestor) Name() string {
	return "TDXCollateralAttestor"
}

func (a *TDXCollateralAttestor) CreateSignedEvidence(ctx context.Context) (*evidence.SignedEvidencePiece, error) {
	ca, err := extractCaFromPckCert(a.PCKCertificate)

	if err != nil {
		return nil, fmt.Errorf("failed to extract ca from pck cert: %w", err)
	}

	pckCrlURL := pcs.PckCrlURL(ca)

	pckCrlHeaders, pckCrlBody, err := a.Getter.Get(pckCrlURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get crl: %w", err)
	}

	pckCrlIntermediateCert, pckCrlRootCert, err := headerToIssuerChain(pckCrlHeaders, pcs.SgxPckCrlIssuerChainPhrase)
	if err != nil {
		return nil, fmt.Errorf("failed to get pck crl certs: %w", err)
	}
	qeHeaders, qeBody, err := getQeIdentity(ctx, a.Getter)

	if err != nil {
		return nil, fmt.Errorf("qe identity get request failed: %w", err)
	}

	qeIdentityIntermediateCert, qeIdentityRootCert, err := headerToIssuerChain(qeHeaders, pcs.SgxQeIdentityIssuerChainPhrase)
	if err != nil {
		return nil, fmt.Errorf("failed to get qe certs: %w", err)
	}
	if len(qeIdentityRootCert.CRLDistributionPoints) != 1 {
		return nil, fmt.Errorf("got more root certificate revocation lists than expected: %w", err)
	}
	rootCrlHeaders, rootCrlBody, err := a.Getter.Get(qeIdentityRootCert.CRLDistributionPoints[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get root crl: %w", err)
	}

	exts, err := pcs.PckCertificateExtensions(a.PCKCertificate)
	if err != nil {
		return nil, err
	}

	tcbHeaders, tcbBody, err := getTcbInfo(ctx, exts.FMSPC, a.Getter)
	if err != nil {
		return nil, fmt.Errorf("failed to get tcb info: %w", err)
	}

	tcbInfoIntermediateCert, tcbInfoRootCert, err := headerToIssuerChain(tcbHeaders, pcs.TcbInfoIssuerChainPhrase)
	if err != nil {
		return nil, fmt.Errorf("failed to get tcb certs: %w", err)
	}

	cb := &evidence.TDXCollateral{
		PckCrlBody:                    pckCrlBody,
		PckCrlHeaders:                 pckCrlHeaders,
		PckCrlRootCertificate:         pckCrlRootCert,
		PckCrlIntermediateCertificate: pckCrlIntermediateCert,
		RootCrlBody:                   rootCrlBody,
		RootCrlHeaders:                rootCrlHeaders,
		QeBody:                        qeBody,
		QeHeaders:                     qeHeaders,
		QeRootCertificate:             qeIdentityRootCert,
		QeIntermediateCertificate:     qeIdentityIntermediateCert,
		TcbBody:                       tcbBody,
		TcbHeaders:                    tcbHeaders,
		TcbRootCertificate:            tcbInfoRootCert,
		TcbIntermediateCertificate:    tcbInfoIntermediateCert,
	}

	cbBytes, err := cb.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate bundle: %w", err)
	}

	return &evidence.SignedEvidencePiece{
		Type:      evidence.TdxCollateral,
		Data:      cbBytes,
		Signature: []byte{},
	}, nil
}

func extractCaFromPckCert(pckCert *x509.Certificate) (string, error) {
	pckIssuer := pckCert.Issuer.CommonName
	if pckIssuer == platformIssuer {
		return platformIssuerID, nil
	}
	if pckIssuer == processorIssuer {
		return processorIssuerID, nil
	}
	return "", errors.New("nil certificate")
}

func headerToIssuerChain(header map[string][]string, phrase string) (*x509.Certificate, *x509.Certificate, error) {
	issuerChain, ok := header[phrase]
	if !ok {
		return nil, nil, fmt.Errorf("%q is empty", phrase)
	}
	if len(issuerChain) != 1 {
		return nil, nil, fmt.Errorf("issuer chain is expected to be of size 1, found %d", len(issuerChain))
	}
	if issuerChain[0] == "" {
		return nil, nil, fmt.Errorf("issuer chain certificates missing in %q", phrase)
	}

	certChain, err := url.QueryUnescape(issuerChain[0])
	if err != nil {
		return nil, nil, fmt.Errorf("unable to decode issuer chain in %q: %w", phrase, err)
	}

	intermediate, rem := pem.Decode([]byte(certChain))
	if intermediate == nil || len(rem) == 0 {
		return nil, nil, fmt.Errorf("could not parse PEM formatted signing certificate in %q", phrase)
	}
	if intermediate.Type != certificateType {
		return nil, nil, fmt.Errorf("the %q PEM block type is %q. Expect %q", phrase, intermediate.Type, certificateType)
	}
	intermediateCert, err := x509.ParseCertificate(intermediate.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("could not interpret DER bytes of signing certificate in %q: %w", phrase, err)
	}

	root, rem := pem.Decode(rem)
	if root == nil || len(rem) != 0 {
		return nil, nil, fmt.Errorf("could not parse PEM formatted root certificate in %q", phrase)
	}
	if root.Type != certificateType {
		return nil, nil, fmt.Errorf("the %q PEM block type is %q. Expect %q", phrase, root.Type, certificateType)
	}
	rootCert, err := x509.ParseCertificate(root.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("could not interpret DER bytes of root certificate in %q: %w", phrase, err)
	}
	return intermediateCert, rootCert, nil
}

func getQeIdentity(ctx context.Context, getter trust.HTTPSGetter) (map[string][]string, []byte, error) {
	qeIdentityURL := pcs.QeIdentityURL()
	header, body, err := trust.GetWith(ctx, getter, qeIdentityURL)
	return header, body, err
}

func getTcbInfo(ctx context.Context, fmspc string, getter trust.HTTPSGetter) (map[string][]string, []byte, error) {
	tcbInfoURL := pcs.TcbInfoURL(fmspc)
	header, body, err := trust.GetWith(ctx, getter, tcbInfoURL)
	return header, body, err
}

func ExtractChainFromQuoteV4(quote *pb.QuoteV4) (*verify.PCKCertificateChain, error) {
	certChainBytes := quote.GetSignedData().GetCertificationData().GetQeReportCertificationData().GetPckCertificateChainData().GetPckCertChain()
	if certChainBytes == nil {
		return nil, verify.ErrPCKCertChainNil
	}

	pck, rem := pem.Decode(certChainBytes)
	if pck == nil || len(rem) == 0 || pck.Type != certificateType {
		return nil, verify.ErrPCKCertChainInvalid
	}
	pckCert, err := x509.ParseCertificate(pck.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not interpret PCK leaf certificate DER bytes: %w", err)
	}

	intermediate, rem := pem.Decode(rem)
	if intermediate == nil || len(rem) == 0 || intermediate.Type != certificateType {
		return nil, verify.ErrPCKCertChainInvalid
	}
	intermediateCert, err := x509.ParseCertificate(intermediate.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not interpret Intermediate CA certificate DER bytes: %w", err)
	}

	root, rem := pem.Decode(rem)
	if root == nil || root.Type != certificateType {
		return nil, verify.ErrPCKCertChainInvalid
	}

	// The final byte of the certificate chain can be a null byte.
	if len(rem) != 0 && !bytes.Equal(rem, []byte{0x00}) {
		return nil, fmt.Errorf("unexpected trailing bytes were found in PCK Certificate Chain: %d byte(s)", len(rem))
	}

	rootCert, err := x509.ParseCertificate(root.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not interpret Root CA certificate DER bytes: %w", err)
	}

	return &verify.PCKCertificateChain{PCKCertificate: pckCert,
		RootCertificate:         rootCert,
		IntermediateCertificate: intermediateCert}, nil
}
