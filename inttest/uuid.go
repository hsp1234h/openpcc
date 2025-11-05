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

package inttest

import (
	"encoding/binary"

	"github.com/google/uuid"
	"github.com/openpcc/openpcc/uuidv7"
)

func DeterministicV7UUID(n int) uuid.UUID {
	baseID := uuidv7.MustParse("01954bd0-da22-7aed-858a-7da965fcee3f")

	tgt := baseID[len(baseID)-8:] // create a slice into the underlying array.
	//nolint:gosec
	binary.BigEndian.PutUint64(tgt, uint64(n)) // modify the underlying array.

	return baseID
}
