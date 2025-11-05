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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	spb "github.com/in-toto/attestation/go/v1"
	"github.com/openpcc/openpcc/gen/protos"
	bundlepb "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/proto"
)

var ErrNoStatement = errors.New("no statement in bundle")

// Verifier provides the configuration for a Verifier.
type VerifierConfig struct {
	// Environment is the sigstore environment to use. Must be [EnvironmentStaging] or [EnvironmentProd].
	Environment Environment `yaml:"environment"`
	// LocalTrustedRootCachePath determines where the trusted root will be cached on the file system. If, empty
	// the local trusted root cache will be disabled (required for read-only file systems).
	LocalTrustedRootCachePath string `yaml:"local_trusted_root_cache_path"`

	// ModTUFBaseURLFunc is an escape hatch to allow modifying the tuf base url.
	// TODO: Solve this in a cleaner way.
	ModTUFBaseURLFunc func(s string) string
}

// DefaultVerifierConfig returns the default (production) verifier config.
func DefaultVerifierConfig() VerifierConfig {
	return VerifierConfig{
		Environment:               EnvironmentProd,
		LocalTrustedRootCachePath: "",
	}
}

// Verifier verifies sigstore bundles. Assumes bundles use sha256 digest hashes.
type Verifier struct {
	verifier *verify.Verifier
}

// NewVerifier creates a new verifier for a given config. The provided HTTP client is only used
// to fetch the sigstore trusted root, it's not used during the verification process itself.
func NewVerifier(cfg VerifierConfig, httpClient *http.Client) (*Verifier, error) {
	err := cfg.Environment.Validate()
	if err != nil {
		return nil, err
	}

	isStaging := cfg.Environment == EnvironmentStaging
	tufClient, err := newTufClient(httpClient, isStaging, cfg.LocalTrustedRootCachePath, cfg.ModTUFBaseURLFunc)
	if err != nil {
		return nil, err
	}

	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get trusted root: %w", err)
	}

	verifier, err := verify.NewVerifier(
		trustedRoot,
		verify.WithTransparencyLog(1),
		verify.WithIntegratedTimestamps(1),
		verify.WithObserverTimestamps(1),
		verify.WithSignedCertificateTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create sigstore verifier: %w", err)
	}

	return &Verifier{
		verifier: verifier,
	}, nil
}

type IdentityPolicy struct {
	OIDCIssuer       string `yaml:"oidc_issuer"`
	OIDCIssuerRegex  string `yaml:"oidc_issuer_regex"`
	OIDCSubject      string `yaml:"oidc_subject"`
	OIDCSubjectRegex string `yaml:"oidc_subject_regex"`
}

// ToProto converts the identity policy to a protobuf representation [protos.IdentityPolicy].
func (p IdentityPolicy) ToProto() *protos.IdentityPolicy {
	pb := &protos.IdentityPolicy_builder{
		OidcIssuer:       &p.OIDCIssuer,
		OidcIssuerRegex:  &p.OIDCIssuerRegex,
		OidcSubject:      &p.OIDCSubject,
		OidcSubjectRegex: &p.OIDCSubjectRegex,
	}
	return pb.Build()
}

// FromProto converts a protobuf representation [protos.IdentityPolicy] to an [IdentityPolicy].
func IdentityPolicyFromProto(pb *protos.IdentityPolicy) IdentityPolicy {
	if pb == nil {
		return IdentityPolicy{}
	}
	return IdentityPolicy{
		OIDCIssuer:       pb.GetOidcIssuer(),
		OIDCIssuerRegex:  pb.GetOidcIssuerRegex(),
		OIDCSubject:      pb.GetOidcSubject(),
		OIDCSubjectRegex: pb.GetOidcSubjectRegex(),
	}
}

type BundleMetadata struct {
	Timestamp time.Time
}

// Verify verifies that the provided data is attested to by bundle b.
func (v *Verifier) Verify(data, b []byte, identity IdentityPolicy) (BundleMetadata, error) {
	_, bMeta, err := v.doVerify(b, verify.WithArtifact(bytes.NewReader(data)), identity)
	return bMeta, err
}

// VerifyHash verifies that the provided hash is attested to by bundle b.
func (v *Verifier) VerifyHash(sha256Hash, b []byte, identity IdentityPolicy) (BundleMetadata, error) {
	_, bMeta, err := v.doVerify(b, verify.WithArtifactDigest("sha256", sha256Hash), identity)
	return bMeta, err
}

// VerifyStatement verifies that the provided data is attested to by bundle b. In addition it returns the
// statement included in the bundle, if there is no statement VerifyStatement will return [ErrNoStatement].
func (v *Verifier) VerifyStatement(data, b []byte, identity IdentityPolicy) (*Statement, BundleMetadata, error) {
	statementPB, bMeta, err := v.doVerify(b, verify.WithArtifact(bytes.NewReader(data)), identity)
	if err != nil {
		return nil, BundleMetadata{}, err
	}

	statement, err := v.handleStatementPB(statementPB)
	if err != nil {
		return nil, BundleMetadata{}, err
	}

	return statement, bMeta, nil
}

// VerifyStatementHash verifies that the provided hash is attested to by bundle b. In addition it returns the
// statement included in the bundle, if there is no statement VerifyStatement will return [ErrNoStatement].
func (v *Verifier) VerifyStatementHash(sha256Hash, b []byte, identity IdentityPolicy) (*Statement, BundleMetadata, error) {
	statementPB, bMeta, err := v.doVerify(b, verify.WithArtifactDigest("sha256", sha256Hash), identity)
	if err != nil {
		return nil, BundleMetadata{}, err
	}

	statement, err := v.handleStatementPB(statementPB)
	if err != nil {
		return nil, BundleMetadata{}, err
	}

	return statement, bMeta, nil
}

// VerifyStatementIntegrity verifies that bundle b is well-formed, signed for a specific identity and has an entry in the transparency log.
//
// It does not verify the statement has a specific signed hash.
//
// In addition it returns the statement included in the bundle, if there is no statement VerifyStatement will
// return [ErrNoStatement].
func (v *Verifier) VerifyStatementIntegrity(b []byte, identity IdentityPolicy) (*Statement, BundleMetadata, error) {
	statementPB, bMeta, err := v.doVerify(b, verify.WithoutArtifactUnsafe(), identity)
	if err != nil {
		// when verify.WithoutArtifactUnsafe is used with a signature-bundle (a bundle without a statament),
		// the sigstore package will return a stringly-typed error with message:
		// "artifact must be provided to verify message signature".
		if strings.Contains(err.Error(), "artifact must be provided to verify message signature") {
			return nil, BundleMetadata{}, ErrNoStatement
		}
		return nil, BundleMetadata{}, err
	}

	statement, err := v.handleStatementPB(statementPB)
	if err != nil {
		return nil, BundleMetadata{}, err
	}

	return statement, bMeta, nil
}

// VerifyStatementPredicateKey verifies the statement against an artifact stored in the predicate key. It expects the predicate key
// to contain base64 encoded data that matches one of the subjects in the statement.
func (v *Verifier) VerifyStatementPredicate(b []byte, predicateKey string, identity IdentityPolicy) (*Statement, BundleMetadata, error) {
	statement, _, err := v.VerifyStatementIntegrity(b, identity)
	if err != nil {
		return nil, BundleMetadata{}, err
	}

	predicateVal, ok := statement.Predicate[predicateKey]
	if !ok {
		return nil, BundleMetadata{}, fmt.Errorf("predicate does not contain %s key", predicateKey)
	}

	base64Val, ok := predicateVal.(string)
	if !ok {
		return nil, BundleMetadata{}, fmt.Errorf("predicate value for key %s does not contain a string but %#v", predicateKey, predicateVal)
	}

	data, err := base64.StdEncoding.DecodeString(base64Val)
	if err != nil {
		return nil, BundleMetadata{}, fmt.Errorf("failed to base64 decode predicate value: %w", err)
	}

	return v.VerifyStatement(data, b, identity)
}

type PredicateProcessor func(*Statement) ([]byte, error)

func (v *Verifier) VerifyStatementWithProcessor(b []byte, processor PredicateProcessor, identity IdentityPolicy) (*Statement, BundleMetadata, error) {
	statement, _, err := v.VerifyStatementIntegrity(b, identity)
	if err != nil {
		return nil, BundleMetadata{}, fmt.Errorf("failed to verify statement integrity: %w", err)
	}

	data, err := processor(statement)
	if err != nil {
		return nil, BundleMetadata{}, fmt.Errorf("failed to get subject data: %w", err)
	}

	return v.VerifyStatement(data, b, identity)
}

func (v *Verifier) doVerify(b []byte, artifactPolicy verify.ArtifactPolicyOption, identity IdentityPolicy) (*spb.Statement, BundleMetadata, error) {
	bpb := &bundlepb.Bundle{}
	err := proto.Unmarshal(b, bpb)
	if err != nil {
		return nil, BundleMetadata{}, fmt.Errorf("failed to unmarshal bundle from protobuf: %w", err)
	}

	sigstoreBundle, err := bundle.NewBundle(bpb)
	if err != nil {
		return nil, BundleMetadata{}, fmt.Errorf("failed to create new sigstore bundle: %w", err)
	}

	certIdentity, err := verify.NewShortCertificateIdentity(identity.OIDCIssuer, identity.OIDCIssuerRegex, identity.OIDCSubject, identity.OIDCSubjectRegex)
	if err != nil {
		return nil, BundleMetadata{}, fmt.Errorf("failed to create certificate identity policy: %w", err)
	}

	policy := verify.NewPolicy(
		artifactPolicy,
		verify.WithCertificateIdentity(certIdentity),
	)

	result, err := v.verifier.Verify(sigstoreBundle, policy)
	if err != nil {
		return nil, BundleMetadata{}, fmt.Errorf("failed to verify: %w", err)
	}

	timestamp, ok := v.findTimestampVerification(result.VerifiedTimestamps)
	if !ok {
		return nil, BundleMetadata{}, errors.New("result is missing timestamp")
	}

	return result.Statement, BundleMetadata{
		Timestamp: timestamp.UTC(),
	}, nil
}

func (*Verifier) handleStatementPB(statementPB *spb.Statement) (*Statement, error) {
	if statementPB == nil {
		return nil, ErrNoStatement
	}

	statement := &Statement{}
	err := statement.UnmarshalProto(statementPB)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal statement protobuf: %w", err)
	}

	return statement, nil
}

func (*Verifier) findTimestampVerification(timestamps []verify.TimestampVerificationResult) (time.Time, bool) {
	for _, timestamp := range timestamps {
		if timestamp.Type == "Tlog" {
			return timestamp.Timestamp, true
		}
	}

	return time.Time{}, false
}

func NewCachedVerifier(verifier *Verifier) *CachedVerifier {
	return &CachedVerifier{
		mu:         sync.RWMutex{},
		delegate:   verifier,
		statements: make(map[string]Statement),
	}
}

type CachedVerifier struct {
	mu         sync.RWMutex
	delegate   *Verifier
	statements map[string]Statement
}

func (v *CachedVerifier) VerifyStatementWithProcessor(b []byte, processor PredicateProcessor, identity IdentityPolicy) (*Statement, BundleMetadata, error) {
	statement, bMeta, err := v.delegate.VerifyStatementWithProcessor(b, processor, identity)
	if err != nil {
		return nil, BundleMetadata{}, err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	hash := sha256.Sum256(b)
	v.statements[hex.EncodeToString(hash[:])] = *statement

	return statement, bMeta, nil
}

func (v *CachedVerifier) VerifyStatementPredicate(b []byte, predicateKey string, identity IdentityPolicy) (*Statement, BundleMetadata, error) {
	statement, bMeta, err := v.delegate.VerifyStatementPredicate(b, predicateKey, identity)
	if err != nil {
		return nil, BundleMetadata{}, err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	hash := sha256.Sum256(b)
	v.statements[hex.EncodeToString(hash[:])] = *statement

	return statement, bMeta, nil
}

func (v *CachedVerifier) CachedStatements() []Statement {
	v.mu.RLock()
	defer v.mu.RUnlock()

	statements := []Statement{}
	for _, statement := range v.statements {
		statements = append(statements, statement)
	}

	return statements
}
