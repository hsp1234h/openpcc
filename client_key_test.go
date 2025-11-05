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
package openpcc_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/openpcc/openpcc"
	"github.com/openpcc/openpcc/gateway"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/keyrotation"
	ctest "github.com/openpcc/openpcc/test"
	"github.com/stretchr/testify/require"
)

func TestOHTTPKeyConfigSelection(t *testing.T) {
	testCases := []struct {
		name               string
		keyRotationPeriods []gateway.KeyRotationPeriodWithID
		expectError        bool
		expectedError      string
	}{
		{
			name: "selects most recent active key",
			keyRotationPeriods: []gateway.KeyRotationPeriodWithID{
				{
					KeyID: 0,
					Period: keyrotation.Period{
						// Key has been active for 1 day.
						// This is the key we anticipate to be used.
						ActiveFrom:  time.Now().Add(-24 * time.Hour),
						ActiveUntil: time.Now().Add(24 * time.Hour),
					},
				},
				{
					KeyID: 1,
					Period: keyrotation.Period{
						// Key has been active for 2 days.
						ActiveFrom:  time.Now().Add(-48 * time.Hour),
						ActiveUntil: time.Now().Add(24 * time.Hour),
					},
				},
				{
					KeyID: 2,
					Period: keyrotation.Period{
						// Key is not yet active.
						ActiveFrom:  time.Now().Add(24 * time.Hour),
						ActiveUntil: time.Now().Add(48 * time.Hour),
					},
				},
			},
			// Verifying that the client is using the correct key is non-trivial given
			// what fields and methods are public on the client.
			// We sneakily only pass 1 key config to the remote config, meaning
			// this test will error if the client logic does NOT select key 0.
			expectError: false,
		},
		{
			name: "no active keys available (inactive)",
			keyRotationPeriods: []gateway.KeyRotationPeriodWithID{
				{
					KeyID: 0,
					Period: keyrotation.Period{
						// Key is not yet active
						ActiveFrom:  time.Now().Add(24 * time.Hour),
						ActiveUntil: time.Now().Add(48 * time.Hour),
					},
				},
			},
			expectError:   true,
			expectedError: "no active OHTTP keys available",
		},
		{
			name: "no active keys available (expired)",
			keyRotationPeriods: []gateway.KeyRotationPeriodWithID{
				{
					KeyID: 0,
					Period: keyrotation.Period{
						// Key is expired
						ActiveFrom:  time.Now().Add(-48 * time.Hour),
						ActiveUntil: time.Now().Add(-24 * time.Hour),
					},
				},
			},
			expectError:   true,
			expectedError: "no active OHTTP keys available",
		},
		{
			name: "key rotation period ID does not match key config ID (should never happen)",
			keyRotationPeriods: []gateway.KeyRotationPeriodWithID{
				{
					KeyID: 3,
					Period: keyrotation.Period{
						// Key is active
						ActiveFrom:  time.Now().Add(-24 * time.Hour),
						ActiveUntil: time.Now().Add(24 * time.Hour),
					},
				},
			},
			expectError:   true,
			expectedError: "no key config found for key ID 3",
		},
	}

	keyConfigs, err := gateway.GenerateKeyConfigs([][]byte{
		test.Must(hex.DecodeString("c742eb47f2fa6b7b0b00272b393640b4d433a65df53f968b3a570fb52473d023")),
	})
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := &ctest.FakeWallet{}
			nodeFinder := &ctest.FakeNodeFinder{}

			cfg := openpcc.DefaultConfig()
			cfg.APIKey = "test api key"
			cfg.APIURL = "localhost:9999"
			authClient := &ctest.FakeAuthClient{
				RouterURLFunc: func() string {
					return "http://example.com/router"
				},
				OHTTPKeyConfigs:         keyConfigs,
				OHTTPKeyRotationPeriods: tc.keyRotationPeriods,
			}

			_, err := openpcc.NewFromConfig(t.Context(), cfg,
				openpcc.WithWallet(w),
				openpcc.WithVerifiedNodeFinder(nodeFinder),
				openpcc.WithRouterPing(false),
				openpcc.WithAuthClient(authClient),
			)

			if tc.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
