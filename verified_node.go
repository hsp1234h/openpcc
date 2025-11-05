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
	"fmt"
	"time"

	"github.com/confidentsecurity/twoway"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/router/api"
)

// VerifiedNode is a compute node for which the attestation has been
// verified and trusted data has been extracted from the evidence.
type VerifiedNode struct {
	Manifest    api.ComputeManifest
	TrustedData evidence.ComputeData
	VerifiedAt  time.Time
}

func (n *VerifiedNode) toCandidate(sealer *twoway.MultiRequestSealer) (api.ComputeCandidate, twoway.ResponseOpenerFunc, error) {
	nodePubKey, err := n.TrustedData.UnmarshalPublicKey()
	if err != nil {
		return api.ComputeCandidate{}, nil, fmt.Errorf("failed to unmarshal public key for node: %w", err)
	}

	encapKey, openerFunc, err := sealer.EncapsulateKey(0, nodePubKey)
	if err != nil {
		return api.ComputeCandidate{}, nil, fmt.Errorf("failed to encapsulate key for node: %w", err)
	}

	return api.ComputeCandidate{
		ID:              n.Manifest.ID,
		EncapsulatedKey: encapKey,
	}, openerFunc, nil
}
