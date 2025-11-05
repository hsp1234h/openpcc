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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/openpcc/openpcc/cserrors"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/transparency"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCachingSigner_Sign(t *testing.T) {
	requireStoredBundle := func(t *testing.T, store transparency.ReadStore, bundle, data []byte) {
		t.Helper()

		finder := transparency.NewBundleFinder(store)
		got, err := finder.FindSignatureBundleByData(t.Context(), data)
		require.NoError(t, err)
		require.Equal(t, bundle, got)
	}

	requireNoStoredBundle := func(t *testing.T, store transparency.ReadStore, data []byte) {
		t.Helper()

		finder := transparency.NewBundleFinder(store)
		got, err := finder.FindSignatureBundleByData(t.Context(), data)
		require.Error(t, err)
		require.ErrorIs(t, err, cserrors.ErrNotFound)
		require.Nil(t, got)
	}

	t.Run("ok, sign new data", func(t *testing.T) {
		t.Parallel()

		bundle := loadHashBundle(t, "bundle-hello-world-1.txt")
		signer := newFakeSigner(bundle)
		store := newTestStore(t)

		cachingSigner := transparency.NewCachingSigner(signer, store)
		gotBundle, err := cachingSigner.Sign(t.Context(), []byte("hello world!"))
		require.NoError(t, err)
		require.Equal(t, bundle, gotBundle)

		requireStoredBundle(t, store, bundle, []byte("hello world!"))
	})

	t.Run("ok, sign same data twice", func(t *testing.T) {
		t.Parallel()

		bundle := loadHashBundle(t, "bundle-hello-world-1.txt")
		signer := newFakeSigner(bundle)
		store := newTestStore(t)

		cachingSigner := transparency.NewCachingSigner(signer, store)
		gotBundle, err := cachingSigner.Sign(t.Context(), []byte("hello world!"))
		require.NoError(t, err)
		require.Equal(t, bundle, gotBundle)

		gotBundle, err = cachingSigner.Sign(t.Context(), []byte("hello world!"))
		require.NoError(t, err)
		require.Equal(t, bundle, gotBundle)

		requireStoredBundle(t, store, bundle, []byte("hello world!"))
	})

	t.Run("ok, sign two different data elements", func(t *testing.T) {
		t.Parallel()

		bundle1 := loadHashBundle(t, "bundle-hello-world-1.txt")
		bundle2 := loadHashBundle(t, "bundle-hello-mars-1.txt")
		signer := newFakeSigner(bundle1, bundle2)
		store := newTestStore(t)

		cachingSigner := transparency.NewCachingSigner(signer, store)
		got, err := cachingSigner.Sign(t.Context(), []byte("hello world!"))
		require.NoError(t, err)
		require.Equal(t, bundle1, got)

		got, err = cachingSigner.Sign(t.Context(), []byte("hello mars!"))
		require.NoError(t, err)
		require.Equal(t, bundle2, got)

		requireStoredBundle(t, store, bundle1, []byte("hello world!"))
		requireStoredBundle(t, store, bundle2, []byte("hello mars!"))
	})

	t.Run("fail, data signing failed", func(t *testing.T) {
		t.Parallel()

		bundle := loadHashBundle(t, "bundle-hello-world-1.txt")
		signer := newFakeSigner(bundle)
		signer.signErr = assert.AnError
		store := newTestStore(t)

		cachingSigner := transparency.NewCachingSigner(signer, store)
		_, err := cachingSigner.Sign(t.Context(), []byte("hello world!"))
		require.Error(t, err)

		requireNoStoredBundle(t, store, []byte("hello world!"))
	})

	t.Run("fail, store insert error", func(t *testing.T) {
		t.Parallel()

		bundle := loadHashBundle(t, "bundle-hello-world-1.txt")
		signer := newFakeSigner(bundle)
		store := &failingWriteStore{
			insertErr: assert.AnError,
		}

		cachingSigner := transparency.NewCachingSigner(signer, store)
		_, err := cachingSigner.Sign(t.Context(), []byte("hello world!"))
		require.Error(t, err)
	})
}

func TestCachingSigner_SignStatement(t *testing.T) {
	// sha256 sum of https://example.com/v1/greeting+plain
	const predicateTypeHash = "f1befeccd5852f523b08b20fff5902637cf8ab8f62e4333aa28b6a83cc7e0793"

	requireStoredBundles := func(t *testing.T, store transparency.ReadStore, bundles [][]byte) {
		t.Helper()

		finder := transparency.NewBundleFinder(store)
		got, err := finder.FindStatementBundles(t.Context(), transparency.StatementBundleQuery{})
		require.NoError(t, err)
		requireEqualCollections(t, bundles, got)
	}

	generateSubjects := func(t *testing.T, n int) []transparency.StatementSubject {
		t.Helper()

		out := make([]transparency.StatementSubject, 0, n)
		for i := range n {
			name := fmt.Sprintf("subject-%v", i)
			hash := sha256.Sum256([]byte(name))
			out = append(out, transparency.StatementSubject{
				Name: name,
				Digest: map[string]string{
					"sha256": hex.EncodeToString(hash[:]),
				},
			})
		}
		return out
	}

	t.Run("ok, sign new statement", func(t *testing.T) {
		t.Parallel()

		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		signer := newFakeSigner(bundle)
		store := newTestStore(t)
		statement := newGreetingStatement(t, "hello world!")

		cachingSigner := transparency.NewCachingSigner(signer, store)
		_, gotBundle, err := cachingSigner.SignStatement(t.Context(), statement)
		require.NoError(t, err)
		require.Equal(t, bundle, gotBundle)

		requireStoredBundles(t, store, [][]byte{bundle})
	})

	t.Run("ok, sign same statement twice", func(t *testing.T) {
		t.Parallel()

		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		signer := newFakeSigner(bundle)
		store := newTestStore(t)
		statement := newGreetingStatement(t, "hello world!")

		cachingSigner := transparency.NewCachingSigner(signer, store)
		_, gotBundle, err := cachingSigner.SignStatement(t.Context(), statement)
		require.NoError(t, err)
		require.Equal(t, bundle, gotBundle)

		requireStoredBundles(t, store, [][]byte{bundle})
	})

	diffStatementsTest := map[string]func(s *transparency.Statement){
		"ok, different statements, same predicate type": func(s *transparency.Statement) {
			sMars := newGreetingStatement(t, "hello mars!")
			*s = *sMars
		},
		"ok, sign statements with different subject hashes": func(s *transparency.Statement) {
			sMars := newGreetingStatement(t, "hello mars!")
			s.Subject[0].Digest = sMars.Subject[0].Digest
		},
		"ok, sign statements with different subject names but same hashes": func(s *transparency.Statement) {
			s.Subject[0].Name += "_other"
		},
		"ok, sign statements with different predicate types": func(s *transparency.Statement) {
			s.PredicateType += "-other"
		},
		"ok, sign statements with different predicate values": func(s *transparency.Statement) {
			s.Predicate["other_data"] = "test"
		},
	}

	for name, modFunc := range diffStatementsTest {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			bundle1 := loadStatementBundle(t, "bundle-hello-world-1.txt")
			// use hello-mars-1 as a valid hardcoded bundle for statement2. In most cases this bundle
			// does not correspond to the statement being signed. But that's fine, in this test we're just using
			// it to check whether the signed bundle gets stored or not.
			bundle2 := loadStatementBundle(t, "bundle-hello-mars-1.txt")
			signer := newFakeSigner(bundle1, bundle2)
			store := newTestStore(t)
			statement1 := newGreetingStatement(t, "hello world!")
			statement2 := newGreetingStatement(t, "hello world!")

			modFunc(statement2)

			cachingSigner := transparency.NewCachingSigner(signer, store)
			_, got, err := cachingSigner.SignStatement(t.Context(), statement1)
			require.NoError(t, err)
			require.Equal(t, bundle1, got)

			_, got, err = cachingSigner.SignStatement(t.Context(), statement2)
			require.NoError(t, err)
			require.Equal(t, bundle2, got)

			requireStoredBundles(t, store, [][]byte{bundle1, bundle2})
		})
	}

	t.Run("ok, sign multi-subject statement", func(t *testing.T) {
		t.Parallel()

		bundle := loadStatementBundle(t, "bundle-conversation-1.txt")
		signer := newFakeSigner(bundle)
		store := newTestStore(t)
		statement := newConversationStatement(t, "hello world!", "goodbye world!")

		cachingSigner := transparency.NewCachingSigner(signer, store)
		_, gotBundle, err := cachingSigner.SignStatement(t.Context(), statement)
		require.NoError(t, err)
		require.Equal(t, bundle, gotBundle)

		requireStoredBundles(t, store, [][]byte{bundle})
	})

	t.Run("ok, sign multi-subject statement, same statement subjects in different oder", func(t *testing.T) {
		t.Parallel()

		bundle := loadStatementBundle(t, "bundle-conversation-1.txt")
		signer := newFakeSigner(bundle)
		store := newTestStore(t)
		statement := newConversationStatement(t, "hello world!", "goodbye world!")
		// swap order of subjects.
		statement.Subject = []transparency.StatementSubject{
			statement.Subject[1], statement.Subject[0],
		}

		cachingSigner := transparency.NewCachingSigner(signer, store)
		_, gotBundle, err := cachingSigner.SignStatement(t.Context(), statement)
		require.NoError(t, err)
		require.Equal(t, bundle, gotBundle)

		requireStoredBundles(t, store, [][]byte{bundle})
	})

	t.Run("ok, sign multi-subject statement, max nr of subjects", func(t *testing.T) {
		t.Parallel()

		// use hello-world-1 as a valid hardcoded bundle for statement. This bundle doesn't correspond to
		// the statement being signed, but we only care about the fact that the bundle is stored so it should be fine.
		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		signer := newFakeSigner(bundle)
		store := newTestStore(t)
		statement := newGreetingStatement(t, "hello world!")
		statement.Subject = generateSubjects(t, 10)

		cachingSigner := transparency.NewCachingSigner(signer, store)
		_, gotBundle, err := cachingSigner.SignStatement(t.Context(), statement)
		require.NoError(t, err)
		require.Equal(t, bundle, gotBundle)

		requireStoredBundles(t, store, [][]byte{bundle})
	})

	t.Run("fail, sign multi-subject statement, over max nr of subjects", func(t *testing.T) {
		t.Parallel()

		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		signer := newFakeSigner(bundle)
		store := newTestStore(t)
		statement := newGreetingStatement(t, "hello world!")
		statement.Subject = generateSubjects(t, 11)

		cachingSigner := transparency.NewCachingSigner(signer, store)
		_, _, err := cachingSigner.SignStatement(t.Context(), statement)
		require.Error(t, err)

		requireStoredBundles(t, store, nil)
	})

	t.Run("fail, invalid statement", func(t *testing.T) {
		t.Parallel()

		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		signer := newFakeSigner(bundle)

		store := newTestStore(t)
		statement := newGreetingStatement(t, "hello world!")
		statement.Subject = nil // missing a subject

		cachingSigner := transparency.NewCachingSigner(signer, store)
		_, _, err := cachingSigner.SignStatement(t.Context(), statement)
		require.Error(t, err)

		requireStoredBundles(t, store, nil)
	})

	t.Run("fail, statement signing failed", func(t *testing.T) {
		t.Parallel()

		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		signer := newFakeSigner(bundle)
		signer.signErr = assert.AnError

		store := newTestStore(t)
		statement := newGreetingStatement(t, "hello world!")

		cachingSigner := transparency.NewCachingSigner(signer, store)
		_, _, err := cachingSigner.SignStatement(t.Context(), statement)
		require.Error(t, err)

		requireStoredBundles(t, store, nil)
	})

	t.Run("fail, store insert error", func(t *testing.T) {
		t.Parallel()

		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		signer := newFakeSigner(bundle)
		store := &failingWriteStore{
			insertErr: assert.AnError,
		}
		store.insertErr = assert.AnError
		statement := newGreetingStatement(t, "hello world!")

		cachingSigner := transparency.NewCachingSigner(signer, store)
		_, _, err := cachingSigner.SignStatement(t.Context(), statement)
		require.Error(t, err)
	})
}

type failingWriteStore struct {
	insertErr error
}

func (s *failingWriteStore) FindByKey(ctx context.Context, key string) ([]byte, error) {
	return nil, cserrors.ErrNotFound
}

func (s *failingWriteStore) Insert(ctx context.Context, key string, bundle []byte) error {
	return s.insertErr
}

func newTestStore(t *testing.T) *transparency.FSStore {
	return transparency.NewFSStore(t.TempDir())
}

type fakeSigner struct {
	bundles [][]byte
	signErr error
}

func newFakeSigner(bundles ...[]byte) *fakeSigner {
	return &fakeSigner{
		bundles: bundles,
	}
}

func (f *fakeSigner) fakeSign() ([]byte, error) {
	if f.signErr != nil {
		return nil, f.signErr
	}

	if len(f.bundles) == 0 {
		return nil, errors.New("no hardcoded bundles left")
	}

	bundle := f.bundles[0]
	f.bundles = f.bundles[1:]
	return bundle, f.signErr
}

func (f *fakeSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	return f.fakeSign()
}

func (f *fakeSigner) SignStatement(ctx context.Context, statement *transparency.Statement) ([]byte, error) {
	return f.fakeSign()
}

func loadHashBundle(t *testing.T, name string) []byte {
	t.Helper()

	content := test.ReadFile(t, test.TextArchiveFS(t, "testdata/hash-bundles.txt"), name)
	bundle, err := base64.StdEncoding.DecodeString(string(content))
	require.NoError(t, err)
	return bundle
}

func loadStatementBundle(t *testing.T, name string) []byte {
	t.Helper()

	content := test.ReadFile(t, test.TextArchiveFS(t, "testdata/statement-bundles.txt"), name)
	bundle, err := base64.StdEncoding.DecodeString(string(content))
	require.NoError(t, err)
	return bundle
}
