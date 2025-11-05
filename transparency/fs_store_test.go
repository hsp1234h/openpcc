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

	"github.com/openpcc/openpcc/cserrors"
	"github.com/openpcc/openpcc/transparency"
	"github.com/stretchr/testify/require"
)

func TestFSStore(t *testing.T) {
	t.Run("ok, insert and find by key", func(t *testing.T) {
		store := transparency.NewFSStore(t.TempDir())

		data := []byte("a")
		err := store.Insert(t.Context(), "insert-and-find/a.txt", data)
		require.NoError(t, err)

		got, err := store.FindByKey(t.Context(), "insert-and-find/a.txt")
		require.NoError(t, err)

		require.Equal(t, data, got)
	})

	t.Run("ok, insert and find by glob", func(t *testing.T) {
		store := transparency.NewFSStore(t.TempDir())

		dataA := []byte("a")
		err := store.Insert(t.Context(), "insert-and-find-by-prefix/a.txt", dataA)
		require.NoError(t, err)

		dataB := []byte("b")
		err = store.Insert(t.Context(), "insert-and-find-by-prefix/b.txt", dataB)
		require.NoError(t, err)

		got, err := store.FindByGlob(t.Context(), "insert-and-find-by-prefix/*.txt")
		require.NoError(t, err)

		requireEqualCollections(t, [][]byte{dataA, dataB}, got)
	})

	t.Run("ok, no data for glob", func(t *testing.T) {
		store := transparency.NewFSStore(t.TempDir())

		got, err := store.FindByGlob(t.Context(), "non-existing/*.txt")
		require.NoError(t, err)
		require.Equal(t, [][]byte(nil), got)
	})

	t.Run("fail, find by key, does not exist", func(t *testing.T) {
		store := transparency.NewFSStore(t.TempDir())

		_, err := store.FindByKey(t.Context(), "test/non-existing.txt")
		require.Error(t, err, cserrors.ErrNotFound)
	})
}

func requireEqualCollections[T any](t *testing.T, want []T, got []T) {
	t.Helper()

	require.Equal(t, len(want), len(got))
	for _, val := range want {
		require.Contains(t, got, val)
	}
}
