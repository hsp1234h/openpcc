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

package transparency

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	openapiclient "github.com/go-openapi/runtime/client"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/proto"
)

type Environment string

const (
	EnvironmentStaging = "staging"
	EnvironmentProd    = "prod"
)

func (e Environment) Validate() error {
	if e != EnvironmentProd && e != EnvironmentStaging {
		return fmt.Errorf("unknown environment: %s", e)
	}
	return nil
}

// SignerConfig provides the configuration for a Signer.
type SignerConfig struct {
	// Environment is the sigstore environment to use. Must be [EnvironmentStaging] or [EnvironmentProd].
	Environment Environment `yaml:"environment"`
	// OIDCToken is the token used to authenticate with fulcio.
	//
	// IMPORTANT: The email address related to this OIDC token will be included in
	// published log entries, in case of a Google Cloud service account this will include
	// both the account ID and project ID.
	OIDCToken string `yaml:"oidc_token"`
	// LocalTrustedRootCachePath determines where the trusted root will be cached on the file system. If, empty
	// the local trusted root cache will be disabled (required for read-only file systems).
	LocalTrustedRootCachePath string `yaml:"local_trusted_root_cache_path"`
}

// Signer is used to sign data or statements.
type Signer struct {
	trustedRoot          *root.TrustedRoot
	certProvider         *sign.Fulcio
	certProviderOpts     *sign.CertificateProviderOptions
	timestampAuthorities []*sign.TimestampAuthority
	transparencyLogs     []sign.Transparency
}

// NewSigner creates a new signer for the given config. The provided http client will
// be used to retrieve the trusted root and to create new entries in the transparency log.
func NewSigner(cfg SignerConfig, httpClient *http.Client) (*Signer, error) {
	if cfg.OIDCToken == "" {
		return nil, errors.New("missing oidc token")
	}

	err := cfg.Environment.Validate()
	if err != nil {
		return nil, err
	}

	isStaging := cfg.Environment == EnvironmentStaging
	tufClient, err := newTufClient(httpClient, isStaging, cfg.LocalTrustedRootCachePath, nil)
	if err != nil {
		return nil, err
	}

	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get trusted root: %w", err)
	}

	var signCfg *root.SigningConfig
	if isStaging {
		signCfg, err = newStagingSigningConfig()
	} else {
		signCfg, err = root.GetSigningConfig(tufClient)
	}
	if err != nil {
		return nil, fmt.Errorf("no signing config: %w", err)
	}

	signer := &Signer{
		trustedRoot: trustedRoot,
	}

	// set up fulcio
	fulcioURL, err := root.SelectService(
		signCfg.FulcioCertificateAuthorityURLs(), []uint32{1}, time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to select fulcio service: %w", err)
	}

	signer.certProvider = sign.NewFulcio(&sign.FulcioOptions{
		BaseURL:   fulcioURL.URL,
		Transport: httpClient.Transport,
	})
	signer.certProviderOpts = &sign.CertificateProviderOptions{
		IDToken: cfg.OIDCToken,
	}

	// setup timestamp authorities
	tsaURLs, err := root.SelectServices(
		signCfg.TimestampAuthorityURLs(), signCfg.TimestampAuthorityURLsConfig(), []uint32{1}, time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to select timestamp authority services: %w", err)
	}

	for _, tsaURL := range tsaURLs {
		signer.timestampAuthorities = append(signer.timestampAuthorities, sign.NewTimestampAuthority(&sign.TimestampAuthorityOptions{
			URL:       tsaURL.URL,
			Transport: httpClient.Transport,
		}))
	}

	// configure rekor
	rekorURLs, err := root.SelectServices(
		signCfg.RekorLogURLs(), signCfg.RekorLogURLsConfig(), []uint32{1}, time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to select rekor service: %w", err)
	}
	for _, rekorURL := range rekorURLs {
		instance, err := rekorInstanceWithHTTPClient(rekorURL.URL, httpClient)
		if err != nil {
			return nil, fmt.Errorf("failed to create rekor instance: %w", err)
		}
		signer.transparencyLogs = append(signer.transparencyLogs, instance)
	}

	return signer, nil
}

// Sign signs the provided data and creates a new entry in the transparancy log. The
// data won't be added to the transparency log, only a sha256 hash of its contents.
//
// Still, don't be publish sensitive data to the transparency log. Hashes can be brute-forced.
//
// IMPORTANT: This can't be reversed, once signed and published to the transparency log, an entry
// wil be visible to the world and can't be deleted.
//
// The email address related to the OIDC token will also be included in the log entry, in case of
// a Google Cloud service account this will include both the account ID and project ID.
//
// The data returned by this method is a protobuf encoded Sigstore Bundle. This is self-contained
// package that can be verified by a verifier.
func (s *Signer) Sign(ctx context.Context, data []byte) ([]byte, error) {
	return s.doSign(ctx, &sign.PlainData{Data: data})
}

// SignStatement signs the provided statement and creates a new entry in the transparency log.
//
// The statement will be stored as an in-toto attestation:
// https://github.com/in-toto/attestation/blob/v0.1.0/spec/README.md
//
// The Predicate and PredicateType of the statement will be part of the entry and will be visible in
// the transparency log.
//
// IMPORTANT: This can't be reversed, once signed and published to the transparency log, an entry
// wil be visible to the world and can't be deleted.
//
// The email address related to the OIDC token will also be included in the log entry, in case of
// a Google Cloud service account this will include both the account ID and project ID.
//
// The data returned by this method is a protobuf encoded Sigstore Bundle. This is self-contained
// package that can be verified by a verifier.
func (s *Signer) SignStatement(ctx context.Context, statement *Statement) ([]byte, error) {
	err := statement.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid statement: %w", err)
	}

	data, err := statement.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal statement to json: %w", err)
	}

	return s.doSign(ctx, &sign.DSSEData{
		PayloadType: "application/vnd.in-toto+json",
		Data:        data,
	})
}

func (s *Signer) doSign(ctx context.Context, content sign.Content) ([]byte, error) {
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ephemeral keypair: %w", err)
	}

	opts := sign.BundleOptions{
		Context:                    ctx,
		TrustedRoot:                s.trustedRoot,
		CertificateProvider:        s.certProvider,
		CertificateProviderOptions: s.certProviderOpts,
		TimestampAuthorities:       s.timestampAuthorities,
		TransparencyLogs:           s.transparencyLogs,
	}

	bundle, err := sign.Bundle(content, keypair, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign bundle: %w", err)
	}

	b, err := proto.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal protobuf bundle: %w", err)
	}

	return b, nil
}

// rekorInstanceWithHTTPClient creates a rekor instance that uses the provided http client. Required
// because unlike other services, rekor does not allow for the injection of a custom client.
func rekorInstanceWithHTTPClient(rekorURL string, httpClient *http.Client) (*sign.Rekor, error) {
	rekorClient, err := rekorclient.GetRekorClient(rekorURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create rekor client: %w", err)
	}

	parsedURL, err := url.Parse(rekorURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rekor url: %w", err)
	}

	transport := openapiclient.NewWithClient(parsedURL.Host, "/", []string{"https"}, httpClient)
	rekorClient.SetTransport(transport)

	return sign.NewRekor(&sign.RekorOptions{
		BaseURL: rekorURL,
		Client:  rekorClient.Entries,
	}), nil
}
