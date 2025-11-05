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
	"context"
	"crypto/rand"
	"log/slog"
	"math/big"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/openpcc/openpcc/auth/credentialing"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/tags"
	"go.opentelemetry.io/otel/codes"
)

// CachedNodeFinder fetches and caches verified nodes for any set of tags.
// Each unique tag combination gets its own cache entry with expiration.
type CachedNodeFinder struct {
	mu     sync.RWMutex
	cfg    CachedNodeFinderConfig
	finder VerifiedNodeFinder
	cache  *lru.Cache[string, *cacheEntry]
}

// cacheEntry represents a cached set of nodes for specific tags
type cacheEntry struct {
	nodes     []VerifiedNode
	expiresAt time.Time
}

type CachedNodeFinderConfig struct {
	// Tags are the Tags for which verified nodes are fetched.
	Tags tags.Tags
	// ExpiresAfter is the amount of time before the cache expires
	ExpiresAfter time.Duration
	MaxCacheSize int
}

func DefaultCachedNodeFinderConfig() CachedNodeFinderConfig {
	return CachedNodeFinderConfig{
		ExpiresAfter: 1 * time.Minute,
		MaxCacheSize: 100,
		Tags:         tags.Tags{},
	}
}

func NewCachedNodeFinder(finder VerifiedNodeFinder, cfg CachedNodeFinderConfig) *CachedNodeFinder {
	cache, err := lru.New[string, *cacheEntry](cfg.MaxCacheSize)
	if err != nil {
		// This shouldn't happen
		panic("failed to create LRU cache: " + err.Error())
	}

	return &CachedNodeFinder{
		cfg:    cfg,
		finder: finder,
		cache:  cache,
	}
}

func (*CachedNodeFinder) Close() error {
	return nil
}

func normalizedCacheKey(tagslist tags.Tags) string {
	if len(tagslist) == 0 {
		return ""
	}

	tagSlice := tagslist.Slice()
	sort.Strings(tagSlice)

	return strings.Join(tagSlice, "|")
}

func (e *cacheEntry) isExpired() bool {
	return e.expiresAt.Before(time.Now())
}

func (f *CachedNodeFinder) FindVerifiedNodes(ctx context.Context, maxNodes int, tagslist tags.Tags) ([]VerifiedNode, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "client.cachedNodeFinder.FindVerifiedNodes")
	defer span.End()

	cacheKey := normalizedCacheKey(tagslist)
	f.mu.RLock()
	entry, exists := f.cache.Get(cacheKey)
	f.mu.RUnlock()
	if exists && !entry.isExpired() {
		span.SetStatus(codes.Ok, "cache hit")
		return f.shuffleNodes(entry.nodes)
	}

	var nodes []VerifiedNode
	if err := backoff.Retry(func() (err error) {
		ctx, span := otelutil.Tracer.Start(ctx, "client.cachedNodeFinder.FindVerifiedNodes.retry")
		defer span.End()

		nodes, err = f.finder.FindVerifiedNodes(ctx, maxNodes, tagslist)
		if err != nil {
			// we assume that the underlying finder already retries on
			// network errors. So any error is permanent with regards to the backoff above.
			return otelutil.RecordError(span, backoff.Permanent(err))
		} else if len(nodes) == 0 {
			return otelutil.Error(span, "no nodes")
		}

		span.SetStatus(codes.Ok, "")
		return nil
	}, backoff.WithContext(backoff.NewExponentialBackOff(), ctx)); err != nil {
		slog.Error("failed to fetch nodes", "error", err)
		return nil, err
	}

	f.mu.Lock()
	newEntry := &cacheEntry{
		nodes:     nodes,
		expiresAt: time.Now().Add(f.cfg.ExpiresAfter),
	}
	f.cache.Add(cacheKey, newEntry)
	f.mu.Unlock()

	span.SetStatus(codes.Ok, "cache miss")
	return f.shuffleNodes(nodes)
}

func (f *CachedNodeFinder) ListCachedVerifiedNodes() ([]VerifiedNode, error) {
	// This is only for the UI so please don't rely on it
	return f.FindVerifiedNodes(context.Background(), 100, f.cfg.Tags)
}

// shuffleNodes returns a shuffled copy of the given nodes.
func (*CachedNodeFinder) shuffleNodes(originalNodes []VerifiedNode) ([]VerifiedNode, error) {
	nodes := slices.Clone(originalNodes)
	if len(nodes) == 0 {
		return nodes, nil
	}

	if err := cryptoShuffle(len(nodes), func(i, j int) {
		nodes[i], nodes[j] = nodes[j], nodes[i]
	}); err != nil {
		return nil, err
	}
	return nodes, nil
}

// Copied from stdlib, replaced math/rand with crypto/rand.
func cryptoShuffle(n int, swap func(i, j int)) error {
	// Fisher-Yates shuffle: https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
	i := n - 1
	for ; i > 1<<31-1-1; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		swap(i, int(j.Int64()))
	}
	for ; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		swap(i, int(j.Int64()))
	}
	return nil
}

func (f *CachedNodeFinder) GetBadge(ctx context.Context) (credentialing.Badge, error) {
	return f.finder.GetBadge(ctx)
}
