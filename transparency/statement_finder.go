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
	"fmt"
	"slices"
)

// StatementFinder queries a store for statements and verifies their integrity.
type StatementFinder struct {
	bundleFinder   *BundleFinder
	verifier       *Verifier
	identityPolicy IdentityPolicy
}

func NewStatementFinder(store ReadStore, verifier *Verifier, identityPolicy IdentityPolicy) *StatementFinder {
	return &StatementFinder{
		bundleFinder:   NewBundleFinder(store),
		verifier:       verifier,
		identityPolicy: identityPolicy,
	}
}

type BundleAndStatement struct {
	Bundle     []byte
	BundleMeta BundleMetadata
	Statement  *Statement
	Key        string
}

func (f *StatementFinder) FindBundleAndStatement(ctx context.Context, s *Statement) (BundleAndStatement, error) {
	key, bundle, err := f.bundleFinder.FindStatementBundle(ctx, s)
	if err != nil {
		return BundleAndStatement{}, err
	}

	statement, bMeta, err := f.verifier.VerifyStatementIntegrity(bundle, f.identityPolicy)
	if err != nil {
		return BundleAndStatement{}, fmt.Errorf("failed to verify integrity of statement bundle: %w", err)
	}

	return BundleAndStatement{
		Bundle:     bundle,
		BundleMeta: bMeta,
		Statement:  statement,
		Key:        key,
	}, nil
}

func (f *StatementFinder) FindStatements(ctx context.Context, q StatementBundleQuery) ([]BundleAndStatement, error) {
	bundles, err := f.bundleFinder.FindStatementBundles(ctx, q)
	if err != nil {
		return nil, err
	}

	out := make([]BundleAndStatement, 0, len(bundles))
	for _, bundle := range bundles {
		statement, bMeta, err := f.verifier.VerifyStatementIntegrity(bundle, f.identityPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to verify integrity of statement bundle: %w", err)
		}
		out = append(out, BundleAndStatement{
			Statement:  statement,
			BundleMeta: bMeta,
			Bundle:     bundle,
		})
	}

	// sort statements by timestamp in descending order (new to old).
	slices.SortFunc(out, func(b1, b2 BundleAndStatement) int {
		return b2.BundleMeta.Timestamp.Compare(b1.BundleMeta.Timestamp)
	})

	return out, nil
}
