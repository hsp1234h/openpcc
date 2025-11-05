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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type ReadStore interface {
	FindByKey(ctx context.Context, key string) ([]byte, error)
	FindByGlob(ctx context.Context, glob string) ([][]byte, error)
}

type BundleFinder struct {
	store ReadStore
}

func NewBundleFinder(store ReadStore) *BundleFinder {
	return &BundleFinder{
		store: store,
	}
}

func (f *BundleFinder) FindSignatureBundleByData(ctx context.Context, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return f.FindSignatureBundleByHash(ctx, hash[:])
}

func (f *BundleFinder) FindSignatureBundleByHash(ctx context.Context, hash []byte) ([]byte, error) {
	err := validateSha256Hash(hash)
	if err != nil {
		return nil, err
	}
	key := "data/" + hex.EncodeToString(hash[:hashLen]) + ".pb"
	return f.store.FindByKey(ctx, key)
}

func (f *BundleFinder) FindStatementBundle(ctx context.Context, statement *Statement) (string, []byte, error) {
	key, err := newStatementBundleKey(statement)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create key: %w", err)
	}

	bundle, err := f.store.FindByKey(ctx, key)
	return key, bundle, err
}

type StatementBundleQuery struct {
	PredicateType string
	Hash          []byte
}

func (f *BundleFinder) FindStatementBundles(ctx context.Context, q StatementBundleQuery) ([][]byte, error) {
	predicateMatcher := "*"
	if q.PredicateType != "" {
		err := validatePredicateType(q.PredicateType)
		if err != nil {
			return nil, err
		}

		predicateMatcher = hexHash([]byte(q.PredicateType))
	}
	digestMatcher := "*.pb"
	if len(q.Hash) > 0 {
		err := validateSha256Hash(q.Hash)
		if err != nil {
			return nil, err
		}

		digestMatcher = "*" + hex.EncodeToString(q.Hash[:hashLen]) + "*.pb"
	}

	glob := "statements/" + predicateMatcher + "/*/" + digestMatcher
	bundles, err := f.store.FindByGlob(ctx, glob)
	if err != nil {
		return nil, fmt.Errorf("failed to find bundles for prefix: %w", err)
	}

	return bundles, nil
}
