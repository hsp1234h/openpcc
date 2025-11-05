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
package verify

import (
	"context"
	"fmt"

	ev "github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/transparency"
	"github.com/openpcc/openpcc/transparency/statements"
)

func ImageSigstoreBundle(
	_ context.Context,
	imageSigstoreBundle *ev.SignedEvidencePiece,
	v TransparencyVerifier,
	identity transparency.IdentityPolicy,
) (*statements.ImageManifest, error) {
	statement, _, err := statements.VerifyImageManifestBundle(imageSigstoreBundle.Data, v, identity)
	if err != nil {
		return nil, fmt.Errorf("failed to verify statement integrity: %w", err)
	}

	return statements.ToImageManifest(statement)
}

type TransparencyVerifier interface {
	VerifyStatementWithProcessor(b []byte, processor transparency.PredicateProcessor, identity transparency.IdentityPolicy) (*transparency.Statement, transparency.BundleMetadata, error)
}
