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

// uuidv7 is a small helper package that wraps github.com/google/uuid and makes it
// easier to work with version 7 uuids.
package uuidv7

import (
	"fmt"

	"github.com/google/uuid"
)

const Version = uuid.Version(7)

// New creates a new V7 UUID.
func New() (uuid.UUID, error) {
	return uuid.NewV7()
}

// MustNew creates a new V7 UUID or panics. Should only be used in tests.
func MustNew() uuid.UUID {
	uid, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}

	return uid
}

// Parse parses a V7 UUID. If the format or version doesn't match, Parse will return an error.
func Parse(s string) (uuid.UUID, error) {
	uid, err := uuid.Parse(s)
	if err != nil {
		return uuid.UUID{}, err
	}

	if uid.Version() != Version {
		return uuid.UUID{}, fmt.Errorf("got uuid of version %d, want version %d", uid.Version(), Version)
	}

	return uid, nil
}

// ParseBytes is the same as [Parse] but accepts a slice of bytes instead of a string.
func ParseBytes(b []byte) (uuid.UUID, error) {
	uid, err := uuid.ParseBytes(b)
	if err != nil {
		return uuid.UUID{}, err
	}

	if uid.Version() != Version {
		return uuid.UUID{}, fmt.Errorf("got uuid of version %d, want version %d", uid.Version(), Version)
	}

	return uid, nil
}

// MustParse parses an UUID V7 or panics. Should only be used in tests.
func MustParse(s string) uuid.UUID {
	uid, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return uid
}
