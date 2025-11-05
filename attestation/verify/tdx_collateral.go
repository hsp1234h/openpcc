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
	"context"
	"crypto/x509"
	"fmt"
	"github.com/openpcc/openpcc/attestation/evidence"
)

func TDXCollateral(
	_ context.Context,
	signedEvidencePiece *evidence.SignedEvidencePiece,
) error {
	collateral := &evidence.TDXCollateral{}
	err := collateral.UnmarshalBinary(signedEvidencePiece.Data)
	if err != nil {
		return fmt.Errorf("failed unmarshal TDX collateral: %w", err)
	}

	tdxRootCert, err := GetTDXRootCert()

	if err != nil {
		return fmt.Errorf("failed to load TDX root cert: %w", err)
	}

	pckCrl, err := x509.ParseRevocationList(collateral.PckCrlBody)

	if err != nil {
		return fmt.Errorf("failed to load PCK CRL: %w", err)
	}
	rootCrl, err := x509.ParseRevocationList(collateral.RootCrlBody)
	if err != nil {
		return fmt.Errorf("failed to load root CRL: %w", err)
	}

	// Verify root CRL is signed by root cert
	err = rootCrl.CheckSignatureFrom(tdxRootCert)
	if err != nil {
		return fmt.Errorf("failed to verify root crl: %w", err)
	}

	// Verify intermediate certificate is signed by root certificate
	err = collateral.PckCrlIntermediateCertificate.CheckSignatureFrom(tdxRootCert)
	if err != nil {
		return fmt.Errorf("failed to verify intermediate certificate signature: %w", err)
	}

	// Verify PCK CRL is signed by intermediate cert
	err = pckCrl.CheckSignatureFrom(collateral.PckCrlIntermediateCertificate)
	if err != nil {
		return fmt.Errorf("failed to verify pck crl: %w", err)
	}

	return nil
}
