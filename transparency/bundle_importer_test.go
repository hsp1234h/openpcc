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

package transparency_test

import (
	"testing"
	"time"

	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/transparency"
	bundlepb "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/stretchr/testify/require"
)

func TestBundleImporter(t *testing.T) {
	requireStoredBundle := func(t *testing.T, store transparency.ReadStore, statement *transparency.Statement, bundle []byte) {
		t.Helper()

		finder := transparency.NewBundleFinder(store)
		_, got, err := finder.FindStatementBundle(t.Context(), statement)
		require.NoError(t, err)
		require.Equal(t, bundle, got)
	}

	requireNoStoredBundles := func(t *testing.T, store transparency.ReadStore) {
		t.Helper()

		finder := transparency.NewBundleFinder(store)
		got, err := finder.FindStatementBundles(t.Context(), transparency.StatementBundleQuery{})
		require.NoError(t, err)
		require.Equal(t, 0, len(got))
	}

	t.Run("ok, import bundle", func(t *testing.T) {
		t.Parallel()

		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)
		store := newTestStore(t)

		want := transparency.BundleAndStatement{
			Bundle: bundle,
			BundleMeta: transparency.BundleMetadata{
				Timestamp: time.Date(2025, time.June, 23, 14, 25, 53, 0, time.UTC),
			},
			Statement: newGreetingStatement(t, "hello world!"),
		}

		importer := transparency.NewBundleImporter(verifier, test.LocalDevIdentityPolicy(), store)
		got, err := importer.ImportStatementBundle(t.Context(), bundle)
		require.NoError(t, err)

		requireEqualBundleAndStatements(t, []transparency.BundleAndStatement{want}, []transparency.BundleAndStatement{got})
		requireStoredBundle(t, store, got.Statement, bundle)

		// import the same bundle again
		got, err = importer.ImportStatementBundle(t.Context(), bundle)
		require.NoError(t, err)
		requireEqualBundleAndStatements(t, []transparency.BundleAndStatement{want}, []transparency.BundleAndStatement{got})
		requireStoredBundle(t, store, got.Statement, bundle)
	})

	t.Run("fail, corrupted bundle", func(t *testing.T) {
		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		bundle = modBundle(t, bundle, func(bpb *bundlepb.Bundle) {
			env := bpb.GetDsseEnvelope()
			require.NotNil(t, env)
			require.Len(t, env.Signatures, 1)
			env.Signatures[0].Sig[0]++
		})
		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)
		store := newTestStore(t)

		importer := transparency.NewBundleImporter(verifier, test.LocalDevIdentityPolicy(), store)
		_, err = importer.ImportStatementBundle(t.Context(), bundle)
		require.Error(t, err)

		requireNoStoredBundles(t, store)
	})
}
