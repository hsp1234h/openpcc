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

package gateway_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/confidentsecurity/ohttp"
	"github.com/confidentsecurity/twoway"
	"github.com/openpcc/openpcc/gateway"
	"github.com/openpcc/openpcc/keyrotation"
	"github.com/stretchr/testify/require"
)

func TestFindSecretKey(t *testing.T) {
	newKeyConfig := func(id byte) ohttp.KeyConfig {
		return ohttp.KeyConfig{
			KeyID: id,
			KemID: hpke.KEM_P256_HKDF_SHA256,
			SymmetricAlgorithms: []ohttp.SymmetricAlgorithm{
				{
					KDFID:  hpke.KDF_HKDF_SHA256,
					AEADID: hpke.AEAD_AES128GCM,
				},
			},
		}
	}

	testCases := []struct {
		name          string
		keyPairs      gateway.KeyPairs
		expectError   bool
		expectedError error
	}{
		{
			name: "active key within validity period",
			keyPairs: gateway.KeyPairs{
				{
					KeyPair: ohttp.KeyPair{
						KeyConfig: newKeyConfig(0),
					},
					Period: keyrotation.Period{
						ActiveFrom:  time.Now().Add(-1 * time.Hour),
						ActiveUntil: time.Now().Add(1 * time.Hour),
					},
				},
			},
			expectError: false,
		},
		{
			name: "expired key should be rejected",
			keyPairs: gateway.KeyPairs{
				{
					KeyPair: ohttp.KeyPair{
						KeyConfig: newKeyConfig(0),
					},
					Period: keyrotation.Period{
						ActiveFrom:  time.Now().Add(-2 * time.Hour),
						ActiveUntil: time.Now().Add(-1 * time.Hour), // expired
					},
				},
			},
			expectError:   true,
			expectedError: errors.New("key expired"),
		},
		{
			name: "future key should be rejected (should never happen)",
			keyPairs: gateway.KeyPairs{
				{
					KeyPair: ohttp.KeyPair{
						KeyConfig: newKeyConfig(0),
					},
					Period: keyrotation.Period{
						ActiveFrom:  time.Now().Add(1 * time.Hour), // not yet active
						ActiveUntil: time.Now().Add(2 * time.Hour),
					},
				},
			},
			expectError:   true,
			expectedError: errors.New("key not yet active"),
		},
		{
			name: "key is not found",
			keyPairs: gateway.KeyPairs{
				{
					KeyPair: ohttp.KeyPair{
						KeyConfig: newKeyConfig(1),
					},
					Period: keyrotation.Period{
						ActiveFrom:  time.Now().Add(-1 * time.Hour),
						ActiveUntil: time.Now().Add(1 * time.Hour),
					},
				},
			},
			expectError:   true,
			expectedError: errors.New("key not found"),
		},
		{
			name: "expired key should be ignored if active key is available",
			keyPairs: gateway.KeyPairs{
				{
					KeyPair: ohttp.KeyPair{
						KeyConfig: newKeyConfig(0),
					},
					Period: keyrotation.Period{
						ActiveFrom:  time.Now().Add(-1 * time.Hour),
						ActiveUntil: time.Now().Add(1 * time.Hour),
					},
				},
				{
					KeyPair: ohttp.KeyPair{
						KeyConfig: newKeyConfig(1),
					},
					Period: keyrotation.Period{
						ActiveFrom:  time.Now().Add(-2 * time.Hour),
						ActiveUntil: time.Now().Add(-1 * time.Hour), // expired
					},
				},
			},
			expectError: false,
		},
		{
			name: "future key should be ignored if active key is available",
			keyPairs: gateway.KeyPairs{
				{
					KeyPair: ohttp.KeyPair{
						KeyConfig: newKeyConfig(0),
					},
					Period: keyrotation.Period{
						ActiveFrom:  time.Now().Add(-1 * time.Hour),
						ActiveUntil: time.Now().Add(1 * time.Hour),
					},
				},
				{
					KeyPair: ohttp.KeyPair{
						KeyConfig: newKeyConfig(1),
					},
					Period: keyrotation.Period{
						ActiveFrom:  time.Now().Add(1 * time.Hour),
						ActiveUntil: time.Now().Add(2 * time.Hour),
					},
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			header := twoway.RequestHeader{
				KeyID:  0,
				KemID:  hpke.KEM_P256_HKDF_SHA256,
				KDFID:  hpke.KDF_HKDF_SHA256,
				AEADID: hpke.AEAD_AES128GCM,
			}

			_, err := tc.keyPairs[0].FindSecretKey(context.Background(), header)

			if tc.expectError {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
