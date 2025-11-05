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
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/openpcc/openpcc/cserrors"
)

// MaxCacheableSubjects is the maximum number of subjects that is allowed in a statement
// that should be cached.
const MaxCacheableSubjects = 10

type DataStatementSigner interface {
	Sign(ctx context.Context, data []byte) ([]byte, error)
	SignStatement(ctx context.Context, statement *Statement) ([]byte, error)
}

type WriteStore interface {
	FindByKey(ctx context.Context, key string) ([]byte, error)
	Insert(ctx context.Context, key string, data []byte) error
}

// CachingSigner wraps a Signer but stores resulting bundles in a [WriteStore]. Before
// a data or a statement is signed, the store is checked for existing bundles that match it.
type CachingSigner struct {
	signer DataStatementSigner
	store  WriteStore
}

func NewCachingSigner(signer DataStatementSigner, store WriteStore) *CachingSigner {
	return &CachingSigner{
		signer: signer,
		store:  store,
	}
}

func (s *CachingSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	key := "data/" + hexHash(data) + ".pb"
	bundle, err := s.store.FindByKey(ctx, key)
	if err != nil {
		if errors.Is(err, cserrors.ErrNotFound) {
			// data doesn't have a stored bundle, publish and return it.
			return s.signAndInsertData(ctx, key, data)
		}
		// other error
		return nil, fmt.Errorf("failed to find bundle: %w", err)
	}

	return bundle, nil
}

func (s *CachingSigner) signAndInsertData(ctx context.Context, key string, data []byte) ([]byte, error) {
	bundle, err := s.signer.Sign(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign statement: %w", err)
	}

	err = s.store.Insert(ctx, key, bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to insert bundle: %w", err)
	}
	return bundle, nil
}

func (s *CachingSigner) SignStatement(ctx context.Context, statement *Statement) (string, []byte, error) {
	key, err := newStatementBundleKey(statement)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create key: %w", err)
	}

	bundle, err := s.store.FindByKey(ctx, key)
	if err != nil {
		if errors.Is(err, cserrors.ErrNotFound) {
			// statement doesn't have a stored bundle, sign and insert one.
			bundle, err := s.signAndInsertStatement(ctx, key, statement)
			return key, bundle, err
		}
		// other error
		return "", nil, fmt.Errorf("failed to find bundle: %w", err)
	}

	return key, bundle, nil
}

func (s *CachingSigner) signAndInsertStatement(ctx context.Context, key string, statement *Statement) ([]byte, error) {
	bundle, err := s.signer.SignStatement(ctx, statement)
	if err != nil {
		return nil, fmt.Errorf("failed to sign statement: %w", err)
	}

	err = s.store.Insert(ctx, key, bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to insert bundle: %w", err)
	}
	return bundle, nil
}

// newStatementBundleKey expects a valid statement.
func newStatementBundleKey(statement *Statement) (string, error) {
	err := statement.Validate()
	if err != nil {
		return "", fmt.Errorf("invalid statement: %w", err)
	}

	if len(statement.Subject) > MaxCacheableSubjects {
		return "", fmt.Errorf("can't create key for statement with more than %d subjects, got %d subjects", MaxCacheableSubjects, len(statement.Subject))
	}

	// Order subjects by name to create stable keys.
	subjects := slices.Clone(statement.Subject)
	slices.SortFunc(subjects, func(a StatementSubject, b StatementSubject) int {
		return strings.Compare(a.Name, b.Name)
	})

	// Two notes on the code below.
	//
	// 1. To be able to cache statements, we need to assign an identity to them
	// based on their values.
	//
	// A statement refers to the same statement when all the following are true:
	// - Both statements have the same set of subject names and all their digests are equal.
	// - They have the same predicate type.
	// - The predicates serialize to the same JSON.
	//
	// 2. To enable retrieving statement bundles by their digests, we need to mention the
	// subject digests in the key. We can then use a glob-based query to retrieve bundles.
	idInput := strings.Builder{}
	hexDigests := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		hexDigest := subject.hexSha256Digest()
		hexDigests = append(hexDigests, hexDigest[:hashLen*2]) // digest is hex encoded

		_, err := idInput.WriteString(subject.Name + hexDigest)
		if err != nil {
			return "", fmt.Errorf("failed to write name to string builder: %w", err)
		}
	}

	_, err = idInput.WriteString(statement.PredicateType)
	if err != nil {
		return "", fmt.Errorf("failed to write predicate type to string builder: %w", err)
	}

	predicateJSON, err := json.Marshal(statement.Predicate)
	if err != nil {
		return "", fmt.Errorf("failed to marshal predicate to json: %w", err)
	}
	_, err = idInput.Write(predicateJSON)
	if err != nil {
		return "", fmt.Errorf("failed to write predicate json to string builder: %w", err)
	}

	predicateTypePart := hexHash([]byte(statement.PredicateType))
	idPart := hexHash([]byte(idInput.String()))
	hexDigestsPart := strings.Join(hexDigests, "_")

	// structure the final key:
	// statements/{predicate_hash}/{id_hash}/{digest_hash}_{digest_hash}_{digest_hash}.pb
	return `statements/` + predicateTypePart + "/" + idPart + "/" + hexDigestsPart + ".pb", nil
}

const hashLen = 12

func hexHash(b []byte) string {
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:hashLen])
}
