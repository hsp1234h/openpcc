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
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/openpcc/openpcc/cserrors"
)

type BundleImporter struct {
	verifier       *Verifier
	identityPolicy IdentityPolicy
	store          WriteStore
}

func NewBundleImporter(verifier *Verifier, identityPolicy IdentityPolicy, store WriteStore) *BundleImporter {
	return &BundleImporter{
		verifier:       verifier,
		identityPolicy: identityPolicy,
		store:          store,
	}
}

func (i *BundleImporter) ImportStatementBundle(ctx context.Context, b []byte) (BundleAndStatement, error) {
	statement, bMeta, err := i.verifier.VerifyStatementIntegrity(b, i.identityPolicy)
	if err != nil {
		return BundleAndStatement{}, fmt.Errorf("failed to verify statement bundle integrity: %w", err)
	}

	key, err := newStatementBundleKey(statement)
	if err != nil {
		return BundleAndStatement{}, fmt.Errorf("failed to create key: %w", err)
	}

	out := BundleAndStatement{
		Bundle:     b,
		BundleMeta: bMeta,
		Statement:  statement,
	}

	bundle, err := i.store.FindByKey(ctx, key)
	if err != nil {
		if errors.Is(err, cserrors.ErrNotFound) {
			// this bundle isn't stored yet, store it.
			err := i.store.Insert(ctx, key, b)
			if err != nil {
				return BundleAndStatement{}, fmt.Errorf("failed to insert bundle: %w", err)
			}
			return out, nil
		}
		return BundleAndStatement{}, fmt.Errorf("failed to find existing bundle: %w", err)
	}

	if !bytes.Equal(bundle, b) {
		// should not happen, means we're writing different bundles for the exact same statement which breaks our storage model.
		return BundleAndStatement{}, errors.New("stored bundle does not match imported bundle even though they have the same key")
	}

	return out, nil
}
