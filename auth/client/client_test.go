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

package client_test

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/confidentsecurity/ohttp"
	"github.com/openpcc/openpcc/auth/client"
	"github.com/openpcc/openpcc/gateway"
	"github.com/openpcc/openpcc/gen/protos"
	"github.com/openpcc/openpcc/httpfmt"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/keyrotation"
	"github.com/openpcc/openpcc/transparency"
	"github.com/openpcc/openpcc/transparency/statements"
	"github.com/stretchr/testify/require"
)

func TestNewAuthClient(t *testing.T) {
	newOHTTPKeyConfigs := func() ohttp.KeyConfigs {
		kc, err := gateway.GenerateKeyConfigs([][]byte{
			test.Must(hex.DecodeString("0f4eda2e6c806018fb1082a6b0d8dc30c3aee556b41ac47cda7db81a57985997")),
		})
		require.NoError(t, err)

		// Update the key ID to match the rotation period.
		kc[0].KeyID = 1
		return kc
	}

	newOHTTPKeyRotationPeriods := func() []gateway.KeyRotationPeriodWithID {
		return []gateway.KeyRotationPeriodWithID{
			{
				KeyID: 1,
				Period: keyrotation.Period{
					ActiveFrom:  time.Date(2025, time.September, 18, 18, 0, 13, 132674000, time.UTC),
					ActiveUntil: time.Date(2026, time.March, 18, 18, 0, 13, 132674000, time.UTC),
				},
			},
		}
	}

	localDevIdPolicy := test.LocalDevIdentityPolicy()

	validConfigResponse := func(t *testing.T) *protos.AuthConfigResponse {
		finder := transparency.NewBundleFinder(test.LocalDevTransparencyFSStore())
		ohttpBundles, err := finder.FindStatementBundles(t.Context(), transparency.StatementBundleQuery{
			PredicateType: statements.OHTTPKeyConfigsPredicateType,
		})
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(ohttpBundles), 1)

		currencyBundles, err := finder.FindStatementBundles(t.Context(), transparency.StatementBundleQuery{
			PredicateType: statements.PublicKeyPredicateType,
		})
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(currencyBundles), 1)

		resp := &protos.AuthConfigResponse{}
		resp.SetRouterUrl("https://example.com/router")
		resp.SetBankUrl("https://example.com/bank")
		resp.SetOhttpKeyConfigsBundle(ohttpBundles[0])
		resp.SetCurrencyKeyBundle(currencyBundles[0])
		ohttpRelay1 := &protos.OHTTPRelay{}
		ohttpRelay1.SetUrl("https://example.com/relay-1")
		ohttpRelay2 := &protos.OHTTPRelay{}
		ohttpRelay2.SetUrl("https://example.com/relay-2")
		resp.SetRelays([]*protos.OHTTPRelay{
			ohttpRelay1, ohttpRelay2,
		})

		resp.SetIdentityPolicy(localDevIdPolicy.ToProto())

		return resp
	}

	t.Run("ok, get remote config", func(t *testing.T) {
		handlerURL := test.RunHandlerWhile(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("cf-authorization") != "test-key" {
				httpfmt.BinaryBadRequest(w, r, "invalid api key")
			}

			if r.URL.Path != "/api/config" || r.Method != http.MethodGet {
				httpfmt.BinaryBadRequest(w, r, "bad request")
			}

			response := validConfigResponse(t)
			httpfmt.WriteBinaryProto(w, r, response)
		}))

		baseCfg := client.DefaultConfig()
		baseCfg.BaseURL = handlerURL
		baseCfg.APIKey = "test-key"

		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)

		want := client.RemoteConfig{
			RouterURL:               "https://example.com/router",
			BankURL:                 "https://example.com/bank",
			OHTTPRelayURLs:          []string{"https://example.com/relay-1", "https://example.com/relay-2"},
			OHTTPKeyConfigs:         newOHTTPKeyConfigs(),
			OHTTPKeyRotationPeriods: newOHTTPKeyRotationPeriods(),
			IdentityPolicy:          localDevIdPolicy,
		}

		t.Run("configured identity policy", func(t *testing.T) {
			cfg := baseCfg
			cfg.TransparencyIdentityPolicy = &localDevIdPolicy

			c, err := client.New(t.Context(), baseCfg, verifier, http.DefaultClient)

			require.NoError(t, err)
			require.Equal(t, want, c.RemoteConfig())
		})

		t.Run("identity policy from remote config", func(t *testing.T) {
			cfg := baseCfg
			cfg.TransparencyIdentityPolicy = nil

			c, err := client.New(t.Context(), baseCfg, verifier, http.DefaultClient)

			require.NoError(t, err)
			require.Equal(t, want, c.RemoteConfig())
		})
	})

	t.Run("fail, tampered with ohttp key configs bundle", func(t *testing.T) {
		handlerURL := test.RunHandlerWhile(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := validConfigResponse(t)
			bundle := response.GetOhttpKeyConfigsBundle()
			bundle[len(bundle)-1]++
			httpfmt.WriteBinaryProto(w, r, response)
		}))

		cfg := client.DefaultConfig()
		cfg.BaseURL = handlerURL
		cfg.APIKey = "test-key"
		cfg.TransparencyIdentityPolicy = &localDevIdPolicy

		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)

		_, err = client.New(t.Context(), cfg, verifier, http.DefaultClient)
		require.Error(t, err)
	})

	t.Run("fail, tampered with currency key bundle", func(t *testing.T) {
		handlerURL := test.RunHandlerWhile(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := validConfigResponse(t)
			bundle := response.GetCurrencyKeyBundle()
			bundle[len(bundle)-1]++
			httpfmt.WriteBinaryProto(w, r, response)
		}))

		cfg := client.DefaultConfig()
		cfg.BaseURL = handlerURL
		cfg.APIKey = "test-key"
		cfg.TransparencyIdentityPolicy = &localDevIdPolicy

		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)

		_, err = client.New(t.Context(), cfg, verifier, http.DefaultClient)
		require.Error(t, err)
	})

	t.Run("fail, error response from /api/config endpoint", func(t *testing.T) {
		handlerURL := test.RunHandlerWhile(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpfmt.BinaryBadRequest(w, r, "oops")
		}))

		cfg := client.DefaultConfig()
		cfg.BaseURL = handlerURL
		cfg.APIKey = "test-key"
		cfg.TransparencyIdentityPolicy = &localDevIdPolicy

		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)

		_, err = client.New(t.Context(), cfg, verifier, http.DefaultClient)
		require.Error(t, err)
	})

	t.Run("fail, can't reach /api/config endpoint", func(t *testing.T) {
		cfg := client.DefaultConfig()
		cfg.BaseURL = fmt.Sprintf("http://127.0.0.1:%d", test.FreePort(t))
		cfg.APIKey = "test-key"
		cfg.TransparencyIdentityPolicy = &localDevIdPolicy
		cfg.ConfigRequestMaxTimeout = time.Millisecond * 100

		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)

		_, err = client.New(t.Context(), cfg, verifier, http.DefaultClient)
		require.Error(t, err)
	})
}
