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

package tpm

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// Below methods are adapted from https://github.com/google/go-tpm/blob/f37a5cab945313cd9e6276a7385145ebbaf5e2bd/tpm2/crypto.go
// TODO: Remove this file once the upstream package is updated

// Pub converts a TPM public key into one recognized by the crypto package.
func Pub(public *tpm2.TPMTPublic) (crypto.PublicKey, error) {
	var publicKey crypto.PublicKey

	switch public.Type {
	case tpm2.TPMAlgRSA:
		parameters, err := public.Parameters.RSADetail()
		if err != nil {
			return nil, errors.New("failed to retrieve the RSA parameters")
		}

		n, err := public.Unique.RSA()
		if err != nil {
			return nil, errors.New("failed to parse and retrieve the RSA modulus")
		}

		publicKey, err = RSAPub(parameters, n)
		if err != nil {
			return nil, errors.New("failed to retrieve the RSA public key")
		}
	case tpm2.TPMAlgECC:
		parameters, err := public.Parameters.ECCDetail()
		if err != nil {
			return nil, errors.New("failed to retrieve the ECC parameters")
		}

		pub, err := public.Unique.ECC()
		if err != nil {
			return nil, errors.New("failed to parse and retrieve the ECC point")
		}

		publicKey, err = ECDSAPub(parameters, pub)
		if err != nil {
			return nil, errors.New("failed to retrieve the ECC public key")
		}
	default:
		return nil, fmt.Errorf("unsupported public key type: %v", public.Type)
	}

	return publicKey, nil
}

// RSAPub converts a TPM RSA public key into one recognized by the rsa package.
func RSAPub(parms *tpm2.TPMSRSAParms, pub *tpm2.TPM2BPublicKeyRSA) (*rsa.PublicKey, error) {
	result := rsa.PublicKey{
		N: big.NewInt(0).SetBytes(pub.Buffer),
		E: int(parms.Exponent),
	}
	// tpm2.TPM considers 65537 to be the default RSA public exponent, and 0 in
	// the parms
	// indicates so.
	if result.E == 0 {
		result.E = 65537
	}
	return &result, nil
}

// ECDSAPub converts a TPM ECC public key into one recognized by the ecdh package
func ECDSAPub(parms *tpm2.TPMSECCParms, pub *tpm2.TPMSECCPoint) (*ecdsa.PublicKey, error) {
	var c elliptic.Curve
	switch parms.CurveID {
	case tpm2.TPMECCNistP256:
		c = elliptic.P256()
	case tpm2.TPMECCNistP384:
		c = elliptic.P384()
	case tpm2.TPMECCNistP521:
		c = elliptic.P521()
	default:
		return nil, fmt.Errorf("unknown curve: %v", parms.CurveID)
	}

	pubKey := ecdsa.PublicKey{
		Curve: c,
		X:     big.NewInt(0).SetBytes(pub.X.Buffer),
		Y:     big.NewInt(0).SetBytes(pub.Y.Buffer),
	}

	return &pubKey, nil
}

// ECDHPub converts a TPM ECC public key into one recognized by the ecdh package
func ECDHPub(parms *tpm2.TPMSECCParms, pub *tpm2.TPMSECCPoint) (*ecdh.PublicKey, error) {
	pubKey, err := ECDSAPub(parms, pub)
	if err != nil {
		return nil, err
	}

	return pubKey.ECDH()
}

// ECCPoint returns an uncompressed ECC Point
func ECCPoint(pubKey *ecdh.PublicKey) (*big.Int, *big.Int, error) {
	b := pubKey.Bytes()
	size, err := elementLength(pubKey.Curve())
	if err != nil {
		return nil, nil, fmt.Errorf("ECCPoint: %w", err)
	}
	return big.NewInt(0).SetBytes(b[1 : size+1]),
		big.NewInt(0).SetBytes(b[size+1:]), nil
}

func elementLength(c ecdh.Curve) (int, error) {
	switch c {
	case ecdh.P256():
		// crypto/internal/nistec/fiat.p256ElementLen
		return 32, nil
	case ecdh.P384():
		// crypto/internal/nistec/fiat.p384ElementLen
		return 48, nil
	case ecdh.P521():
		// crypto/internal/nistec/fiat.p521ElementLen
		return 66, nil
	default:
		return 0, fmt.Errorf("unknown element length for curve: %v", c)
	}
}
