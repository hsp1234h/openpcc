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

package openpcc

import (
	"time"

	"github.com/openpcc/openpcc/transparency"
)

var (
	// DefaultAPIURL is a variable so it can be set during build time.
	DefaultAPIURL = ""
)

// IdentityPolicySource enumerates the different options for where the identity policy
// should be sourced from.
type IdentityPolicySource int

const (
	// IdentityPolicySourceConfigured indicates that the identity policy is configured in
	// directly when instantiating the client. This is the default.
	IdentityPolicySourceConfigured IdentityPolicySource = iota
	// IdentityPolicySourceRemote indicates that the identity policy is sourced from the
	// remote config.
	// WARNING: This is not safe and should only be used for testing/development.
	IdentityPolicySourceUnsafeRemote
)

// Config allows for configuration of clients via YAML files.
type Config struct {
	// APIKey is the CONFSEC API Key
	APIKey string `yaml:"api_key"`
	// PingRouter pings the router as part of startup if enabled
	PingRouter bool `yaml:"ping_router"`
	// APIURL is the url of the confsec API.
	APIURL string `yaml:"api_url"`
	// OHTTPRelayURL is the url of the ohttp relay. If empty, it will be
	// sourced from the remote config returned by the auth service.
	OHTTPRelayURL string `yaml:"ohttp_relay_url"`

	// MaxCandidateNodes is the maximum number of nodes the client will
	// consider as candidates for handling a request. The router picks
	// one of these candidates to fullfil the request.
	MaxCandidateNodes int `yaml:"max_candidate_nodes"`
	// MaxPrefetchedCandidateNodes is the maximum number of candidate nodes that will be pre-fetched
	// if the client uses the standard node finder.
	MaxPrefetchedCandidateNodes int `yaml:"max_prefetched_candidate_nodes"`
	// DefaultRequestParams are the default request parameters.
	DefaultRequestParams RequestParams `yaml:"default_request_params"`
	// MaxCreditAmountPerRequest is the maximum credit amount (inclusive) that can be provided
	// via DefaultRequestParams or per request override.
	//
	// This option provides a safety mechanism to prevent inadvertently
	// withdrawing large amounts of credits. In case this maximum is violated,
	// the client will return [ErrMaxCreditAmountViolated].
	MaxCreditAmountPerRequest int64 `yaml:"max_credit_amount_per_request"`

	// ConcurrentRequestsTarget is the target number of concurrent requests the client will make.
	// This is primarily used to determine the number of credits held by the wallet that are
	// available to be used immediately.
	ConcurrentRequestsTarget int `yaml:"concurrent_requests_target"`

	// TransparencyVerifier is the configuration for the sigstore bundle verifier.
	TransparencyVerifier transparency.VerifierConfig `yaml:"verify"`

	// TransparencyIdentityPolicySource is the source of the identity policy used to
	// verify the remote config returned by the auth service.
	TransparencyIdentityPolicySource IdentityPolicySource `yaml:"remote_config_identity_policy_source"`

	// TransparencyIdentityPolicy is the identity policy used to verify the remote config returned by the auth service.
	TransparencyIdentityPolicy *transparency.IdentityPolicy `yaml:"remote_config_identity_policy"`

	// WalletCloseTimeout is the maximum amount of time the client will wait for the wallet to close.
	WalletCloseTimeout time.Duration `yaml:"wallet_close_timeout"`

	// build allows for build specific configuration.
	// see client_fake.go and client_real.go.
	build buildConfig
}

// DefaultConfig returns a new instance of Config with default values set.
func DefaultConfig() Config {
	cfg := Config{
		APIKey: "",
		APIURL: DefaultAPIURL,
		TransparencyVerifier: transparency.VerifierConfig{
			Environment:               transparency.EnvironmentProd,
			LocalTrustedRootCachePath: "./.confsec/.sigstore-cache",
		},
		PingRouter:                       true,
		MaxCandidateNodes:                3,
		MaxPrefetchedCandidateNodes:      3,
		DefaultRequestParams:             DefaultRequestParams(),
		ConcurrentRequestsTarget:         2,
		TransparencyIdentityPolicySource: IdentityPolicySourceConfigured,
		WalletCloseTimeout:               90 * time.Second,
	}

	return cfg
}
