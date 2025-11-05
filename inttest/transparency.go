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

package inttest

import (
	"net/http"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/openpcc/openpcc/transparency"
	"github.com/openpcc/openpcc/transparency/statements"
	"github.com/stretchr/testify/require"
)

func moduleRootPath() string {
	_, fn, _, _ := runtime.Caller(0)
	return filepath.Join(fn, "../../")
}

func LocalDevLatestCurrencyKeyBundle(t *testing.T) []byte {
	verifier, err := LocalDevVerifier()
	require.NoError(t, err)
	finder := transparency.NewStatementFinder(LocalDevTransparencyFSStore(), verifier, LocalDevIdentityPolicy())

	// for now we assume that all public keys are currency keys, this won't be the case forever.
	results, err := finder.FindStatements(t.Context(), transparency.StatementBundleQuery{
		PredicateType: statements.PublicKeyPredicateType,
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(results), 1)

	// results are ordered new to old
	return results[0].Bundle
}

func LocalDevLatestOHTTPKeyConfigsBundle(t *testing.T) []byte {
	verifier, err := LocalDevVerifier()
	require.NoError(t, err)
	finder := transparency.NewStatementFinder(LocalDevTransparencyFSStore(), verifier, LocalDevIdentityPolicy())

	results, err := finder.FindStatements(t.Context(), transparency.StatementBundleQuery{
		PredicateType: statements.OHTTPKeyConfigsPredicateType,
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(results), 1)

	// results are ordered new to old
	return results[0].Bundle
}

func LocalDevTransparencyFSStore() *transparency.FSStore {
	rootPath := moduleRootPath()
	p := filepath.Join(rootPath, "dev/sigstore-bundles")
	return transparency.NewFSStore(p)
}

func LocalDevVerifierConfig() transparency.VerifierConfig {
	return transparency.VerifierConfig{
		Environment:               "staging",
		LocalTrustedRootCachePath: filepath.Join(moduleRootPath(), ".sigstore-cache"),
	}
}

func LocalDevVerifier() (*transparency.Verifier, error) {
	return transparency.NewVerifier(LocalDevVerifierConfig(), &http.Client{
		Timeout: 30 * time.Second,
	})
}

func LocalDevSigner(t *testing.T, oidcToken string) *transparency.Signer {
	signer, err := transparency.NewSigner(transparency.SignerConfig{
		Environment:               "staging",
		OIDCToken:                 oidcToken,
		LocalTrustedRootCachePath: filepath.Join(moduleRootPath(), ".sigstore-cache"),
	}, &http.Client{
		Timeout: 30 * time.Second,
	})
	require.NoError(t, err)
	return signer
}

func LocalDevIdentityPolicy() transparency.IdentityPolicy {
	return transparency.IdentityPolicy{
		// TODO(CS-1015): Once the currency key is also signed via GH actions, update this regex.
		OIDCIssuerRegex:  "^https://accounts.google.com$|^https://token.actions.githubusercontent.com$",
		OIDCSubjectRegex: "^https://github.com/confidentsecurity/T/.github/workflows.*|^sigstore-signer@sigstore-test-461110.iam.gserviceaccount.com$",
	}
}
