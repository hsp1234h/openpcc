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

package statements_test

import (
	"errors"
	"testing"

	"github.com/MicahParks/jwkset"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
	"github.com/openpcc/openpcc/transparency"
	"github.com/openpcc/openpcc/transparency/statements"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRSAPublicKey(t *testing.T) {
	newStatement := func() *transparency.Statement {
		// base64 encoded version of the following jwk:
		// {"kty":"RSA","use":"sig","kid":"test-0","n":"4b3FO0vEQ2YcQDVrAW1AikkuFqBj_7Fv4cC20RsHe_etGIhXcNIrijV9qYcqxoBuZno11dEMEZGhEknSnDtNy0EkuMmg18w-GdjxceiKJNNtmzJZs-EM9KbUABn3gCkfOUbIPVYiboHK5XU2W5X9AcF7XtMLHZpTxeMDDuUUTHU","e":"AQAB"}
		jwkBase64 := `eyJrdHkiOiJSU0EiLCJ1c2UiOiJzaWciLCJraWQiOiJ0ZXN0LTAiLCJuIjoiNGIzRk8wdkVRMlljUURWckFXMUFpa2t1RnFCal83RnY0Y0MyMFJzSGVfZXRHSWhYY05JcmlqVjlxWWNxeG9CdVpubzExZEVNRVpHaEVrblNuRHROeTBFa3VNbWcxOHctR2RqeGNlaUtKTk50bXpKWnMtRU05S2JVQUJuM2dDa2ZPVWJJUFZZaWJvSEs1WFUyVzVYOUFjRjdYdE1MSFpwVHhlTUREdVVVVEhVIiwiZSI6IkFRQUIifQ==`
		return &transparency.Statement{
			Subject: []transparency.StatementSubject{
				{
					Name: "jwk",
					Digest: map[string]string{
						"sha256": "cbf08aa11db7ef612d73370684e54d680e24fd76af9438eb48eacd6855513ea5",
					},
				},
			},
			PredicateType: "https://confident.security/v1/public-key",
			Predicate: map[string]any{
				"jwkRaw": jwkBase64,
			},
		}
	}

	t.Run("ok, to and from statement", func(t *testing.T) {
		privKey := anonpaytest.CurrencyKey()
		wantStatement := newStatement()

		gotStatement, err := statements.FromRSAPublicKey(&privKey.PublicKey, statements.RSAPublicKeyClaims{
			Use:   jwkset.UseSig,
			KeyID: "test-0",
		})
		require.NoError(t, err)
		require.Equal(t, wantStatement, gotStatement)

		gotPubKey, err := statements.ToRSAPublicKey(gotStatement, func(claims statements.RSAPublicKeyClaims) error {
			if claims.KeyID != "test-0" {
				return errors.New("invalid key ID")
			}
			if claims.Use != jwkset.UseSig {
				return errors.New("invalid use")
			}
			return nil
		})
		require.NoError(t, err)

		require.Equal(t, &privKey.PublicKey, gotPubKey)
	})

	t.Run("fail, claim verification fails", func(t *testing.T) {
		statement := newStatement()

		_, err := statements.ToRSAPublicKey(statement, func(claims statements.RSAPublicKeyClaims) error {
			return assert.AnError
		})
		require.Error(t, err)
		require.ErrorIs(t, err, assert.AnError)
	})

	invalidStatements := map[string]func(s *transparency.Statement){
		"fail, invalid statement": func(s *transparency.Statement) {
			s.Subject = []transparency.StatementSubject{}
		},
		"fail, missing jwkRaw in predicate": func(s *transparency.Statement) {
			delete(s.Predicate, "jwkRaw")
		},
		"fail, included jwkRaw does not match digest": func(s *transparency.Statement) {
			// base64 encoded jwk for key id test-1 instead of test-0
			s.Predicate["jwkRaw"] = `eyJrdHkiOiJSU0EiLCJ1c2UiOiJzaWciLCJraWQiOiJ0ZXN0LTEiLCJuIjoid2prSGVvZkJtVDJHUnQxWkZkNXhTcGZTVzJJSDl2UTNlUV9BXzUzM3hkY2Uyc2FhN2dqT1VlUEhhXzJwM2p1V0h0SFUwemprLURGMHBfZVVxY2VjS1lJdXllZWVValBCdlYwZlVqVG96eVNJVE11TTVtdzNlSGY2b2ZUNGpjWFJ4Y0ZfQVVFMjNDaEVZMWtHblRNT3RvaUhhelNFOUowdXkwUmFkdHJzeUJjQmJqTnBleHY1Mm41dWRTaVdaRnNuYnp4RXJ0cGZRcHpucFI5ckVlMnF0SzZtZ3dNYXpvZGR5MExQTlQxUlkycUlzMlhnUUJWZGZ0akMtcHFzdU1wX2p4cTlvY21OTGFicnFIaVd3REo2SVpoOVFrdWR1aWY0SEN1YzlVcjhMVkNqNXdDQjlLR0VQTWJWMkRiMTczS2J5Y212SF9qS0F5QjNwWWl3bDFEdHVRIiwiZSI6IkFRQUIifQ==`
		},
		"fail, wrong subject": func(s *transparency.Statement) {
			s.Subject[0].Name = "abc"
		},
		"fail, unexpected extra subject": func(s *transparency.Statement) {
			s.Subject = append(s.Subject, transparency.StatementSubject{
				Name: "extra-subject",
				Digest: map[string]string{
					"sha256": "7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9",
				},
			})
		},
	}

	for name, tc := range invalidStatements {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			statement := newStatement()
			tc(statement)

			_, err := statements.ToRSAPublicKey(statement, func(claims statements.RSAPublicKeyClaims) error {
				return nil
			})
			require.Error(t, err)
		})
	}
}
