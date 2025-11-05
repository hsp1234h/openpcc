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

package openpcc_test

import (
	"context"
	"testing"
	"time"

	"github.com/openpcc/openpcc"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/router/api"
	"github.com/openpcc/openpcc/tags"
	ctest "github.com/openpcc/openpcc/test"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCachedNodeFinder_FindVerifiedNodes(t *testing.T) {
	t.Run("EnsureCache", func(t *testing.T) {
		cfg := openpcc.DefaultCachedNodeFinderConfig()
		cfg.ExpiresAfter = 1 * time.Second
		testTags := test.Must(tags.FromSlice([]string{"llm", "ollama"}))

		var invokeN int
		f := openpcc.NewCachedNodeFinder(&ctest.FakeNodeFinder{
			FindVerifiedNodesFunc: func(ctx context.Context, maxNodes int, tags tags.Tags) ([]openpcc.VerifiedNode, error) {
				invokeN++
				return []openpcc.VerifiedNode{
					{Manifest: api.ComputeManifest{ID: uuidv7.MustNew(), Tags: tags}},
					{Manifest: api.ComputeManifest{ID: uuidv7.MustNew(), Tags: tags}},
					{Manifest: api.ComputeManifest{ID: uuidv7.MustNew(), Tags: tags}},
				}, nil
			},
		}, cfg)

		result, err := f.FindVerifiedNodes(t.Context(), 3, testTags)
		require.NoError(t, err)
		require.Equal(t, 3, len(result))
		require.Equal(t, 1, invokeN)

		for _, node := range result {
			require.True(t, node.Manifest.Tags.ContainsAll(testTags))
		}

		// Fetch again and ensure nodes aren't fetched twice.
		result, err = f.FindVerifiedNodes(t.Context(), 3, testTags)
		require.NoError(t, err)
		require.Equal(t, 3, len(result))
		require.Equal(t, 1, invokeN)

		// Wait for expiration & fetch again.
		time.Sleep(cfg.ExpiresAfter)
		result, err = f.FindVerifiedNodes(t.Context(), 3, testTags)
		require.NoError(t, err)
		require.Equal(t, 3, len(result))
		require.Equal(t, 2, invokeN)

		require.NoError(t, f.Close())
	})

	t.Run("EnsureRandomOrder", func(t *testing.T) {
		cfg := openpcc.DefaultCachedNodeFinderConfig()
		cfg.ExpiresAfter = 1 * time.Second
		testTags := test.Must(tags.FromSlice([]string{"llm", "ollama"}))

		f := openpcc.NewCachedNodeFinder(&ctest.FakeNodeFinder{
			FindVerifiedNodesFunc: func(ctx context.Context, maxNodes int, tags tags.Tags) ([]openpcc.VerifiedNode, error) {
				nodes := make([]openpcc.VerifiedNode, 100)
				for i := range nodes {
					nodes[i] = openpcc.VerifiedNode{Manifest: api.ComputeManifest{ID: uuidv7.MustNew(), Tags: tags}}
				}
				return nodes, nil
			},
		}, cfg)

		result0, err := f.FindVerifiedNodes(t.Context(), 100, testTags)
		require.NoError(t, err)
		require.Equal(t, 100, len(result0))

		result1, err := f.FindVerifiedNodes(t.Context(), 100, testTags)
		require.NoError(t, err)
		require.Equal(t, 100, len(result1))

		require.NotEqual(t, result0, result1)
	})

	t.Run("CacheDifferentTags", func(t *testing.T) {
		cfg := openpcc.DefaultCachedNodeFinderConfig()
		cfg.ExpiresAfter = 10 * time.Second // Long enough to test caching

		var invokeN int
		f := openpcc.NewCachedNodeFinder(&ctest.FakeNodeFinder{
			FindVerifiedNodesFunc: func(ctx context.Context, maxNodes int, tags tags.Tags) ([]openpcc.VerifiedNode, error) {
				invokeN++
				return []openpcc.VerifiedNode{
					{Manifest: api.ComputeManifest{ID: uuidv7.MustNew(), Tags: tags}},
					{Manifest: api.ComputeManifest{ID: uuidv7.MustNew(), Tags: tags}},
					{Manifest: api.ComputeManifest{ID: uuidv7.MustNew(), Tags: tags}},
				}, nil
			},
		}, cfg)

		firstTags := test.Must(tags.FromSlice([]string{"llm", "ollama"}))
		result, err := f.FindVerifiedNodes(t.Context(), 3, firstTags)
		require.NoError(t, err)
		require.Equal(t, 3, len(result))
		require.Equal(t, 1, invokeN)

		secondTags := test.Must(tags.FromSlice([]string{"foo", "bar"}))
		result, err = f.FindVerifiedNodes(t.Context(), 3, secondTags)
		require.NoError(t, err)
		require.Equal(t, 3, len(result))
		require.Equal(t, 2, invokeN)

		result, err = f.FindVerifiedNodes(t.Context(), 3, firstTags)
		require.NoError(t, err)
		require.Equal(t, 3, len(result))
		require.Equal(t, 2, invokeN) // Should not increase

		result, err = f.FindVerifiedNodes(t.Context(), 3, secondTags)
		require.NoError(t, err)
		require.Equal(t, 3, len(result))
		require.Equal(t, 2, invokeN) // Should not increase
	})

	t.Run("fail, error from underlying finder", func(t *testing.T) {
		cfg := openpcc.DefaultCachedNodeFinderConfig()
		cfg.ExpiresAfter = 1 * time.Second
		testTags := test.Must(tags.FromSlice([]string{"llm", "ollama"}))

		var invokeN int
		f := openpcc.NewCachedNodeFinder(&ctest.FakeNodeFinder{
			FindVerifiedNodesFunc: func(ctx context.Context, maxNodes int, tags tags.Tags) ([]openpcc.VerifiedNode, error) {
				invokeN++
				if invokeN < 2 {
					return nil, assert.AnError
				}
				return []openpcc.VerifiedNode{}, nil
			},
		}, cfg)

		_, err := f.FindVerifiedNodes(t.Context(), 3, testTags)
		require.ErrorIs(t, err, assert.AnError)
	})

	t.Run("Backoff/NoNodes", func(t *testing.T) {
		cfg := openpcc.DefaultCachedNodeFinderConfig()
		cfg.ExpiresAfter = 1 * time.Second
		testTags := test.Must(tags.FromSlice([]string{"llm", "ollama"}))

		var invokeN int
		f := openpcc.NewCachedNodeFinder(&ctest.FakeNodeFinder{
			FindVerifiedNodesFunc: func(ctx context.Context, maxNodes int, tags tags.Tags) ([]openpcc.VerifiedNode, error) {
				invokeN++
				if invokeN < 2 {
					return []openpcc.VerifiedNode{}, nil
				}
				return []openpcc.VerifiedNode{
					{Manifest: api.ComputeManifest{ID: uuidv7.MustNew(), Tags: tags}},
					{Manifest: api.ComputeManifest{ID: uuidv7.MustNew(), Tags: tags}},
					{Manifest: api.ComputeManifest{ID: uuidv7.MustNew(), Tags: tags}},
				}, nil
			},
		}, cfg)

		result, err := f.FindVerifiedNodes(t.Context(), 3, testTags)
		require.NoError(t, err)
		require.Equal(t, 3, len(result))
		require.Equal(t, 2, invokeN)
	})
}
