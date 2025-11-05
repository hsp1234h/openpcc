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
	"bytes"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/confidentsecurity/ohttp"
	"github.com/openpcc/openpcc/gateway"
	"github.com/openpcc/openpcc/keyrotation"
	"github.com/openpcc/openpcc/transparency"
	"github.com/openpcc/openpcc/transparency/statements"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOHTTPKeyConfigs(t *testing.T) {
	newOHTTPKeyConfigs := func() ohttp.KeyConfigs {
		pubKey, _ := hpke.KEM_P256_HKDF_SHA256.Scheme().DeriveKeyPair(bytes.Repeat([]byte("0"), 32))

		kc := ohttp.KeyConfig{
			KeyID:     0,
			KemID:     hpke.KEM_P256_HKDF_SHA256,
			PublicKey: pubKey,
			SymmetricAlgorithms: []ohttp.SymmetricAlgorithm{
				{
					KDFID:  hpke.KDF_HKDF_SHA256,
					AEADID: hpke.AEAD_AES128GCM,
				},
				{
					KDFID:  hpke.KDF_HKDF_SHA384,
					AEADID: hpke.AEAD_AES256GCM,
				},
			},
		}

		return ohttp.KeyConfigs{kc}
	}

	newStatement := func() *transparency.Statement {
		return &transparency.Statement{
			Subject: []transparency.StatementSubject{
				{
					Name: "ohttp-keys",
					Digest: map[string]string{
						"sha256": "a63d8ccecc353c63c009f545deccb4a88d7b0694bec68c89af960759c72ef731",
					},
				},
				{
					Name: "key-rotation-periods",
					Digest: map[string]string{
						"sha256": "dab792c32862f1ca5063469fb3869668b9888d883c76d4b0ee23c456e78e9160",
					},
				},
			},
			PredicateType: "https://confident.security/v2/ohttp-keys",
			Predicate: map[string]any{
				// base64 encoded version of the ohttp key configs returned by newOHTTPKeyConfigs.
				"ohttpKeys":          `AE4AABAElYTrb3PnL3Q2Tb9UQib/Y384X+wi76F390I33mlcBjPmJptZ2QksTEz7yC2+kq65dIeltQjJQsWrS//eJulq1wAIAAEAAQACAAI=`,
				"keyRotationPeriods": `W3siYWN0aXZlX2Zyb20iOiIyMDI1LTAxLTAxVDAwOjAwOjAwWiIsImFjdGl2ZV91bnRpbCI6IjIwMzUtMDEtMDFUMDA6MDA6MDBaIiwia2V5X2lkIjowfV0=`,
			},
		}
	}

	t.Run("ok, to and from statement", func(t *testing.T) {
		keyConfigs := newOHTTPKeyConfigs()

		wantStatement := newStatement()

		activeFrom, err := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
		require.NoError(t, err)

		activeUntil, err := time.Parse(time.RFC3339, "2035-01-01T00:00:00Z")
		require.NoError(t, err)

		keyRotationPeriods := []gateway.KeyRotationPeriodWithID{
			{
				KeyID: 0,
				Period: keyrotation.Period{
					ActiveFrom:  activeFrom,
					ActiveUntil: activeUntil,
				},
			},
		}

		gotStatement, err := statements.FromOHTTPKeyConfigs(keyConfigs, keyRotationPeriods)
		require.NoError(t, err)

		// Check everything except Subject order
		require.Equal(t, wantStatement.PredicateType, gotStatement.PredicateType)
		require.Equal(t, wantStatement.Predicate, gotStatement.Predicate)

		// Check Subject elements match regardless of order
		assert.ElementsMatch(t, wantStatement.Subject, gotStatement.Subject)

		gotKeyConfigs, gotKeyRotationPeriods, err := statements.ToOHTTPKeyConfigs(gotStatement)
		require.NoError(t, err)

		require.Equal(t, keyConfigs, gotKeyConfigs)
		require.Equal(t, keyRotationPeriods, gotKeyRotationPeriods)
	})

	type errorTestCase struct {
		name        string
		modFunc     func(s *transparency.Statement)
		expectedErr string
	}

	invalidStatements := []errorTestCase{
		{
			name: "fail, invalid statement",
			modFunc: func(s *transparency.Statement) {
				s.Subject = []transparency.StatementSubject{}
			},
			expectedErr: "expected 2 subjects, got 0 subjects",
		},
		{
			name: "fail, missing ohttpKeys in predicate",
			modFunc: func(s *transparency.Statement) {
				delete(s.Predicate, "ohttpKeys")
			},
			expectedErr: "missing ohttpKeys in predicate",
		},
		{
			name: "fail, missing keyRotationPeriods in predicate",
			modFunc: func(s *transparency.Statement) {
				delete(s.Predicate, "keyRotationPeriods")
			},
			expectedErr: "missing keyRotationPeriods in predicate",
		},
		{
			name: "fail, included ohttpKeys does not match digest",
			modFunc: func(s *transparency.Statement) {
				// base64 encoded ohttp key for key id 1 instead of 0
				s.Predicate["ohttpKeys"] = `AE4BABAElYTrb3PnL3Q2Tb9UQib/Y384X+wi76F390I33mlcBjPmJptZ2QksTEz7yC2+kq65dIeltQjJQsWrS//eJulq1wAIAAEAAQACAAI=`
			},
			expectedErr: "raw ohttp key configs and statement digest don't match",
		},
		{
			name: "fail, included keyRotationPeriods does not match digest",
			modFunc: func(s *transparency.Statement) {
				// base64 encoded key rotation IDs for key id 1 instead of 0
				s.Predicate["keyRotationPeriods"] = `W3siYWN0aXZlX2Zyb20iOiIyMDI1LTAxLTAxVDAwOjAwOjAwWiIsImFjdGl2ZV91bnRpbCI6IjIwMzUtMDEtMDFUMDA6MDA6MDBaIiwia2V5X2lkIjoxfV0=`
			},
			expectedErr: "raw ohttp key rotation periods and statement digest don't match",
		},
		{
			name: "fail, wrong subject",
			modFunc: func(s *transparency.Statement) {
				s.Subject[0].Name = "abc"
			},
			expectedErr: "unexpected subject name abc",
		},
		{
			name: "fail, missing subject",
			modFunc: func(s *transparency.Statement) {
				s.Subject = s.Subject[1:]
			},
			expectedErr: "expected 2 subjects, got 1 subjects",
		},
		{
			name: "fail, unexpected extra subject",
			modFunc: func(s *transparency.Statement) {
				s.Subject = append(s.Subject, transparency.StatementSubject{
					Name: "extra-subject",
					Digest: map[string]string{
						"sha256": "7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9",
					},
				})
			},
			expectedErr: "expected 2 subjects, got 3 subjects",
		},
	}

	for _, tc := range invalidStatements {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			statement := newStatement()
			tc.modFunc(statement)

			_, _, err := statements.ToOHTTPKeyConfigs(statement)
			require.Error(t, err)
			// Important we double check that we received the anticipated error,
			// else we could be masking other errors.
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}
