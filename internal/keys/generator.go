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

package keys

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/openpcc/openpcc/gateway"
)

// GenerateOHTTPKeySeed generates a new OHTTP key seed and returns it as a hex string
func GenerateOHTTPKeySeed() (string, error) {
	kemID, _, _ := gateway.Suite.Params()
	seedSize := kemID.Scheme().SeedSize()

	seed := make([]byte, seedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", fmt.Errorf("failed to generate random seed: %w", err)
	}

	return hex.EncodeToString(seed), nil
}
