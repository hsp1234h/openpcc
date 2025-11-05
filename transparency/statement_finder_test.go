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
	"testing"
	"time"

	"github.com/openpcc/openpcc/cserrors"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/transparency"
	bundlepb "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/stretchr/testify/require"
)

func TestStatementFinder(t *testing.T) {
	t.Run("ok, no results", func(t *testing.T) {
		store := &hardcodedReadStore{}
		identity := test.LocalDevIdentityPolicy()
		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)
		finder := transparency.NewStatementFinder(store, verifier, identity)

		got, err := finder.FindStatements(t.Context(), transparency.StatementBundleQuery{})
		require.NoError(t, err)

		requireEqualBundleAndStatements(t, nil, got)
	})

	t.Run("ok, ordered by timestamp descending", func(t *testing.T) {
		bundle1 := loadStatementBundle(t, "bundle-hello-world-1.txt")
		bundle2 := loadStatementBundle(t, "bundle-hello-world-2.txt")
		bundle3 := loadStatementBundle(t, "bundle-hello-world-3.txt")
		store := &hardcodedReadStore{
			bundles: [][]byte{
				bundle1,
				bundle3,
				bundle2,
			},
		}

		want := []transparency.BundleAndStatement{
			{
				Bundle: bundle3,
				BundleMeta: transparency.BundleMetadata{
					Timestamp: time.Date(2025, time.June, 23, 14, 27, 17, 0, time.UTC),
				},
				Statement: newGreetingStatement(t, "hello world!"),
			},
			{
				Bundle: bundle2,
				BundleMeta: transparency.BundleMetadata{
					Timestamp: time.Date(2025, time.June, 23, 14, 26, 57, 0, time.UTC),
				},
				Statement: newGreetingStatement(t, "hello world!"),
			},
			{
				Bundle: bundle1,
				BundleMeta: transparency.BundleMetadata{
					Timestamp: time.Date(2025, time.June, 23, 14, 25, 53, 0, time.UTC),
				},
				Statement: newGreetingStatement(t, "hello world!"),
			},
		}

		identity := test.LocalDevIdentityPolicy()
		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)
		finder := transparency.NewStatementFinder(store, verifier, identity)

		got, err := finder.FindStatements(t.Context(), transparency.StatementBundleQuery{})
		require.NoError(t, err)

		requireEqualBundleAndStatements(t, want, got)
	})

	t.Run("ok, find bundle and statement", func(t *testing.T) {
		bundle := loadStatementBundle(t, "bundle-hello-world-1.txt")
		store := &hardcodedReadStore{
			bundles: [][]byte{
				bundle,
			},
		}

		want := transparency.BundleAndStatement{
			Bundle: bundle,
			BundleMeta: transparency.BundleMetadata{
				Timestamp: time.Date(2025, time.June, 23, 14, 25, 53, 0, time.UTC),
			},
			Statement: newGreetingStatement(t, "hello world!"),
		}

		identity := test.LocalDevIdentityPolicy()
		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)
		finder := transparency.NewStatementFinder(store, verifier, identity)

		got, err := finder.FindBundleAndStatement(t.Context(), want.Statement)
		require.NoError(t, err)

		requireEqualBundleAndStatements(t, []transparency.BundleAndStatement{want}, []transparency.BundleAndStatement{got})
	})

	t.Run("fail, corrupted bundle", func(t *testing.T) {
		bundle1 := loadStatementBundle(t, "bundle-hello-world-1.txt")
		bundle2 := loadStatementBundle(t, "bundle-hello-world-2.txt")
		bundle3 := loadStatementBundle(t, "bundle-hello-world-3.txt")

		bundle2 = modBundle(t, bundle2, func(bpb *bundlepb.Bundle) {
			env := bpb.GetDsseEnvelope()
			require.NotNil(t, env)
			require.Len(t, env.Signatures, 1)
			env.Signatures[0].Sig[0]++
		})

		store := &hardcodedReadStore{
			bundles: [][]byte{
				bundle1,
				bundle3,
				bundle2,
			},
		}

		identity := test.LocalDevIdentityPolicy()
		verifier, err := test.LocalDevVerifier()
		require.NoError(t, err)
		finder := transparency.NewStatementFinder(store, verifier, identity)

		_, err = finder.FindStatements(t.Context(), transparency.StatementBundleQuery{})
		require.Error(t, err)
	})
}

type hardcodedReadStore struct {
	bundles [][]byte
}

func (s *hardcodedReadStore) FindByGlob(ctx context.Context, pattern string) ([][]byte, error) {
	return s.bundles, nil
}

func (s *hardcodedReadStore) FindByKey(ctx context.Context, key string) ([]byte, error) {
	if len(s.bundles) == 0 {
		return nil, cserrors.ErrNotFound
	}
	return s.bundles[0], nil
}

func requireEqualBundleAndStatements(t *testing.T, want, got []transparency.BundleAndStatement) {
	t.Helper()

	require.Equal(t, len(want), len(got))
	for i, item := range want {
		require.Equal(t, item.Bundle, got[i].Bundle)
		require.Equal(t, item.BundleMeta, got[i].BundleMeta)
		requireEqualStatement(t, item.Statement, got[i].Statement)
	}
}
