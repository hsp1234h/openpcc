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

	"github.com/openpcc/openpcc/transparency"
	"github.com/stretchr/testify/require"
)

func TestBundleFinder_FindStatementBundles(t *testing.T) {
	// other cases tested as part of caching signer tests.

	t.Run("ok, query none", func(t *testing.T) {
		t.Parallel()

		store := newTestStore(t)
		finder := transparency.NewBundleFinder(store)
		bundles, err := finder.FindStatementBundles(t.Context(), transparency.StatementBundleQuery{})
		require.NoError(t, err)
		require.Len(t, bundles, 0)
	})

	t.Run("ok, find multi-subject statement bundle by each hash", func(t *testing.T) {
		t.Parallel()

		bundle := loadStatementBundle(t, "bundle-conversation-1.txt")
		signer := newFakeSigner(bundle)
		store := newTestStore(t)
		statement := newConversationStatement(t, "hello world!", "goodbye world!")

		cachingSigner := transparency.NewCachingSigner(signer, store)
		_, _, err := cachingSigner.SignStatement(t.Context(), statement)
		require.NoError(t, err)

		finder := transparency.NewBundleFinder(store)
		got, err := finder.FindStatementBundles(t.Context(), transparency.StatementBundleQuery{
			Hash: mustHexDecode(helloWorldHash),
		})
		require.NoError(t, err)
		require.Equal(t, [][]byte{bundle}, got)

		got, err = finder.FindStatementBundles(t.Context(), transparency.StatementBundleQuery{
			Hash: mustHexDecode(goodbyeWorldHash),
		})
		require.NoError(t, err)
		require.Equal(t, [][]byte{bundle}, got)
	})

	t.Run("ok, find statement bundle by statement", func(t *testing.T) {
		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		signer := newFakeSigner(bundle)
		store := newTestStore(t)
		statement := newGreetingStatement(t, "hello world!")

		cachingSigner := transparency.NewCachingSigner(signer, store)
		_, _, err := cachingSigner.SignStatement(t.Context(), statement)
		require.NoError(t, err)

		finder := transparency.NewBundleFinder(store)
		key, got, err := finder.FindStatementBundle(t.Context(), statement)
		require.NoError(t, err)
		require.Equal(t, bundle, got)
		require.Equal(t, key, "statements/f1befeccd5852f523b08b20f/bd91c027d0994c8965c6580e/7509e5bda0c762d2bac7f90d.pb")
	})
}
