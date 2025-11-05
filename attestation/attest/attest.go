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

package attest

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/openpcc/openpcc/attestation/evidence"
)

// Attestor returns signed evidence for a compute node.
type Attestor interface {
	CreateSignedEvidence(ctx context.Context) (*evidence.SignedEvidencePiece, error)
	Name() string
}

func checkTDXInDmesg() bool {
	cmd := exec.Command("dmesg")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), "Memory Encryption Features active: Intel TDX")
}

func checkSEVSNPInDmesg() bool {
	cmd := exec.Command("dmesg")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), "Memory Encryption Features active: AMD SEV")
}

func GetTEEType() (evidence.TEEType, error) {
	// Test if /dev/sev-guest exists, if so, return SevSnp
	if _, err := os.Stat("/dev/sev-guest"); err == nil {
		return evidence.SevSnp, nil
	}
	// Test if /dev/tdx_guest exists, if so, return Tdx
	// It's not a typo that this is snake_case and the other is kebab-case
	if _, err := os.Stat("/dev/tdx_guest"); err == nil {
		return evidence.Tdx, nil
	}

	if checkTDXInDmesg() {
		return evidence.Tdx, nil
	}

	if checkSEVSNPInDmesg() {
		return evidence.SevSnp, nil
	}

	// If neither exists, return NoTEE
	return evidence.NoTEE, nil
}
