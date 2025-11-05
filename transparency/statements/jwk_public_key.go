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

package statements

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MicahParks/jwkset"
	"github.com/openpcc/openpcc/transparency"
)

const PublicKeyPredicateType = "https://confident.security/v1/public-key"

func VerifyPublicKeyBundle(b []byte, v *transparency.Verifier, idPolicy transparency.IdentityPolicy) (*transparency.Statement, transparency.BundleMetadata, error) {
	return v.VerifyStatementPredicate(b, "jwkRaw", idPolicy)
}

// FromJWK creates a public key statement for the provided JWK.
func FromJWK(jwk jwkset.JWK) (*transparency.Statement, error) {
	msg, err := json.Marshal(jwk.Marshal())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal jwk to json: %w", err)
	}

	// subject is the data that will get hashed and signed.
	subject := map[string][]byte{
		"jwk": msg,
	}

	// predicate contains claims made by this statement.
	predicate := map[string]any{
		"jwkRaw": base64.StdEncoding.EncodeToString(msg),
	}

	return transparency.NewStatement(subject, PublicKeyPredicateType, predicate), nil
}

// ToJWK attempts to extract the JWK from the given statement.
func ToJWK(statement *transparency.Statement) (jwkset.JWK, error) {
	err := statement.Validate()
	if err != nil {
		return jwkset.JWK{}, fmt.Errorf("invalid statement: %w", err)
	}

	if statement.PredicateType != PublicKeyPredicateType {
		return jwkset.JWK{}, fmt.Errorf("invalid predicate type. want %s, got %s", PublicKeyPredicateType, statement.PredicateType)
	}

	jwkRaw, err := signedJWKRaw(statement)
	if err != nil {
		return jwkset.JWK{}, err
	}

	jwk, err := jwkset.NewJWKFromRawJSON(jwkRaw, jwkset.JWKMarshalOptions{}, jwkset.JWKValidateOptions{})
	if err != nil {
		return jwkset.JWK{}, fmt.Errorf("failed to unmarshal jwk from raw jwk: %w", err)
	}

	return jwk, nil
}

// RSAPublicKeyClaims are the claims included in a RSAPublicKey statement.
type RSAPublicKeyClaims struct {
	KeyID string
	Use   jwkset.USE
}

// FromRSAPublicKey creates a new statement for the given key and claims.
func FromRSAPublicKey(key *rsa.PublicKey, claims RSAPublicKeyClaims) (*transparency.Statement, error) {
	jwk, err := jwkset.NewJWKFromKey(key, jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{
			USE: claims.Use,
			KID: claims.KeyID,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create jwk for key: %w", err)
	}

	return FromJWK(jwk)
}

type RSAPublicKeyClaimVerifier func(claims RSAPublicKeyClaims) error

// ToRSAPublicKey attempts to interpret and verify the provided statements as a JWK Statement included a RSA Public Key.
func ToRSAPublicKey(statement *transparency.Statement, verifierFunc RSAPublicKeyClaimVerifier) (*rsa.PublicKey, error) {
	if verifierFunc == nil {
		return nil, errors.New("missing claims verifier")
	}

	jwk, err := ToJWK(statement)
	if err != nil {
		return nil, err
	}

	m := jwk.Marshal()
	err = verifierFunc(RSAPublicKeyClaims{
		Use:   m.USE,
		KeyID: m.KID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify claims: %w", err)
	}

	pubKey, ok := jwk.Key().(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("jwk is not a RSA Public Key")
	}

	return pubKey, nil
}

func signedJWKRaw(statement *transparency.Statement) ([]byte, error) {
	if len(statement.Subject) != 1 {
		return nil, fmt.Errorf("expected a single jwk subject, got %d subjects", len(statement.Subject))
	}
	if statement.Subject[0].Name != "jwk" {
		return nil, fmt.Errorf("expected subject to be jwk but got %s", statement.Subject[0].Name)
	}

	predicateVal, ok := statement.Predicate["jwkRaw"]
	if !ok {
		return nil, errors.New("missing raw jwk predicate entry")
	}

	jwkRawBase64, ok := predicateVal.(string)
	if !ok {
		return nil, fmt.Errorf("raw jwk should be a string, is %#v", predicateVal)
	}

	jwkRaw, err := base64.StdEncoding.DecodeString(jwkRawBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode raw jwk: %w", err)
	}

	// Most important check. This statement contains the data that was signed (the JWK),
	// we need to check if the hash from the statement actually matches this data.
	match, err := statement.Subject[0].Sha256Match(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("error matching hashes: %w", err)
	}
	if !match {
		return nil, errors.New("raw jwk and statement digest don't match")
	}

	return jwkRaw, nil
}
