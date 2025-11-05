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

package client

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/cenkalti/backoff/v4"
	"github.com/confidentsecurity/ohttp"
	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/gateway"
	"github.com/openpcc/openpcc/gen/protos"
	"github.com/openpcc/openpcc/httpretry"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/transparency"
	"github.com/openpcc/openpcc/transparency/statements"
	"google.golang.org/protobuf/proto"
)

// RemoteConfig is the environment-specific remote config as returned by the /api/config endpoint.
type RemoteConfig struct {
	RouterURL               string
	BankURL                 string
	OHTTPRelayURLs          []string
	OHTTPKeyConfigs         ohttp.KeyConfigs
	OHTTPKeyRotationPeriods []gateway.KeyRotationPeriodWithID
	IdentityPolicy          transparency.IdentityPolicy
}

func fetchRemoteConfig(ctx context.Context, cfg Config, httpClient *http.Client) (*protos.AuthConfigResponse, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "auth/client.fetchRemoteConfig")
	defer span.End()

	configURL := cfg.BaseURL + "/api/config"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create config request: %w", err)
	}

	req.Header.Set(APIKeyHeader, cfg.APIKey)
	req.Header.Set("X-Currency-Date", time.Unix(anonpay.RoundDownNonceTimestamp(time.Now().Unix()), 0).UTC().Format(http.TimeFormat))

	// retry for timeout period
	bckoff := backoff.NewExponentialBackOff(
		backoff.WithMaxElapsedTime(cfg.ConfigRequestMaxTimeout),
	)
	resp, err := httpretry.DoWith(httpClient, req, bckoff, httpretry.Retry5xx)
	if err != nil {
		return nil, fmt.Errorf("failed to do config request: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading config from body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error getting config, got status %d: url=%s, body=%s", resp.StatusCode, configURL, body)
	}

	var configResp protos.AuthConfigResponse
	if err := proto.Unmarshal(body, &configResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &configResp, nil
}

func verifyRemoteConfig(cfg Config, resp *protos.AuthConfigResponse, verifier TransparencyVerifier) (RemoteConfig, *rsa.PublicKey, error) {
	remoteCfg, err := newRemoteConfigFromURLs(resp)
	if err != nil {
		return RemoteConfig{}, nil, err
	}

	var idPolicy transparency.IdentityPolicy
	if cfg.TransparencyIdentityPolicy != nil {
		idPolicy = *cfg.TransparencyIdentityPolicy
	} else {
		slog.Warn("no transparency identity policy provided, using identity policy from remote config. THIS IS UNSAFE AND SHOULD NOT BE USED IN PRODUCTION.")
		idPolicy = remoteCfg.IdentityPolicy
	}

	// verify and retrieve the currency key
	currencyKeyStatement, _, err := verifier.VerifyStatementPredicate(resp.GetCurrencyKeyBundle(), "jwkRaw", idPolicy)
	if err != nil {
		return RemoteConfig{}, nil, fmt.Errorf("failed to verify currency key statement: %w", err)
	}

	currencyKey, err := statements.ToRSAPublicKey(currencyKeyStatement, func(claims statements.RSAPublicKeyClaims) error {
		if claims.Use != jwkset.UseSig {
			return fmt.Errorf("expected a signing key, got %v", claims.Use)
		}
		return nil
	})
	if err != nil {
		return RemoteConfig{}, nil, fmt.Errorf("failed to convert statement to a public key: %w", err)
	}

	// verify and retrieve the ohttp key configs
	ohttpKeysStatement, _, err := verifier.VerifyStatementPredicate(resp.GetOhttpKeyConfigsBundle(), "ohttpKeys", idPolicy)
	if err != nil {
		return RemoteConfig{}, nil, fmt.Errorf("failed to verify ohttp keys statement: %w", err)
	}

	ohttpKeys, ohttpKeyRotationPeriods, err := statements.ToOHTTPKeyConfigs(ohttpKeysStatement)
	if err != nil {
		return RemoteConfig{}, nil, fmt.Errorf("failed to convert statement to ohttp key configs: %w", err)
	}
	remoteCfg.OHTTPKeyConfigs = ohttpKeys
	remoteCfg.OHTTPKeyRotationPeriods = ohttpKeyRotationPeriods

	return remoteCfg, currencyKey, nil
}

func newRemoteConfigFromURLs(resp *protos.AuthConfigResponse) (RemoteConfig, error) {
	routerURL, err := url.Parse(resp.GetRouterUrl())
	if err != nil {
		return RemoteConfig{}, fmt.Errorf("invalid router url: %w", err)
	}

	bankURL, err := url.Parse(resp.GetBankUrl())
	if err != nil {
		return RemoteConfig{}, fmt.Errorf("invalid bank url: %w", err)
	}

	if len(resp.GetRelays()) == 0 {
		return RemoteConfig{}, errors.New("need at least one relay, got 0")
	}

	relayURLs := make([]string, 0, len(resp.GetRelays()))
	for i, relay := range resp.GetRelays() {
		relayURL, err := url.Parse(relay.GetUrl())
		if err != nil {
			return RemoteConfig{}, fmt.Errorf("invalid relay url in relay %d: %w", i, err)
		}
		relayURLs = append(relayURLs, relayURL.String())
	}

	return RemoteConfig{
		RouterURL:      routerURL.String(),
		BankURL:        bankURL.String(),
		OHTTPRelayURLs: relayURLs,
		IdentityPolicy: transparency.IdentityPolicyFromProto(resp.GetIdentityPolicy()),
	}, nil
}
