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

package secrets

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"slices"
)

const redacted = "REDACTED"

// String is a type that represents a secret value that should not be exposed
// in logs or other output.
type String struct {
	value []byte
}

// NewString creates a new secret value from a string.
func NewString(value string) String {
	return String{value: []byte(value)}
}

// Consume returns the secret value zeros out the value.
func (s *String) Consume() string {
	value := string(s.value)
	s.Destroy()
	return value
}

// Destroy explicitly zeros out the secret.
func (s *String) Destroy() {
	// overwrite the value with zeros.
	for i := range s.value {
		s.value[i] = 0
	}
	// clear the slice.
	s.value = s.value[:0]
}

// Copy returns a copy of the secret.
func (s *String) Copy() *String {
	value := make([]byte, len(s.value))
	copy(value, s.value)
	return &String{value: value}
}

// Bytes returns the secret as a byte slice.
func (s *String) Bytes() []byte {
	return slices.Clone(s.value)
}

// Equal compares two secrets in constant time.
func (s String) Equal(other String) bool {
	if len(s.value) != len(other.value) {
		return false
	}

	return subtle.ConstantTimeCompare(s.value, other.value) == 1
}

// String implements fmt.Stringer.
func (String) String() string {
	return redacted
}

// MarshalJSON implements json.Marshaler.
func (String) MarshalJSON() ([]byte, error) {
	return json.Marshal(redacted)
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *String) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	s.value = []byte(str)
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (String) MarshalText() ([]byte, error) {
	return []byte(redacted), nil
}

// MarshalYAML implements yaml.Marshaler.
func (String) MarshalYAML() (any, error) {
	return redacted, nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (String) MarshalBinary() ([]byte, error) {
	return []byte(redacted), nil
}

// LogValue implements slog.LogValuer.
func (String) LogValue() slog.Value {
	return slog.StringValue(redacted)
}
