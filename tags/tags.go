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

package tags

import (
	"errors"
	"fmt"
	"strings"
)

const MaxTagLength = 512

// Tags is a set of tags.
type Tags map[string]struct{}

// FromSlice creates a set of tags from the given tags. Duplicates are filtered out.
func FromSlice(rawTags []string) (Tags, error) {
	out := make(map[string]struct{}, len(rawTags))
	for _, tag := range rawTags {
		if len(tag) > MaxTagLength {
			return nil, fmt.Errorf("tag over max length, got %d, want %d", len(tag), MaxTagLength)
		}
		out[tag] = struct{}{}
	}

	return out, nil
}

func StripTagKey(rawTags []string, tagKey string) ([]string, error) {
	tagValues := []string{}
	for _, tag := range rawTags {
		parts := strings.SplitN(tag, "=", 2)
		if len(parts) != 2 || parts[0] != tagKey {
			return nil, fmt.Errorf("invalid raw tag: %s. Expected tag to have prefix '%s'", tag, tagKey+"=")
		}
		tagValues = append(tagValues, parts[1])
	}
	return tagValues, nil
}

func (t Tags) AddTag(tag string) error {
	if len(tag) > MaxTagLength {
		return fmt.Errorf("tag over max length, got %d, want %d", len(tag), MaxTagLength)
	}
	t[tag] = struct{}{}
	return nil
}

func (t Tags) AddTagPair(keyName string, valueName string) error {
	tag := keyName + "=" + valueName
	if len(tag) > MaxTagLength {
		return fmt.Errorf("tag over max length, got %d, want %d", len(tag), MaxTagLength)
	}
	if strings.Contains(keyName, "=") {
		return errors.New("invalid tag pair. Key name must not contain '='")
	}
	if strings.Contains(valueName, "=") {
		return errors.New("invalid tag pair. Value must not contain '='")
	}

	t[tag] = struct{}{}
	return nil
}

// Slice returns the set of tags as a slice of strings.
func (t Tags) Slice() []string {
	tags := make([]string, 0, len(t))
	for tag := range t {
		tags = append(tags, tag)
	}
	return tags
}

func (t Tags) RemoveKey(keyName string) int {
	numDeleted := 0
	for tag := range t {
		if strings.HasPrefix(tag, keyName+"=") {
			delete(t, tag)
			numDeleted++
		}
	}

	return numDeleted
}

func (t Tags) Contains(tagName string) bool {
	_, ok := t[tagName]
	return ok
}

func (t Tags) ContainsKey(keyName string) bool {
	for tag := range t {
		if strings.HasPrefix(tag, keyName+"=") {
			return true
		}
	}
	return false
}

func (t Tags) ContainsPair(keyName string, valueName string) bool {
	tagName := keyName + "=" + valueName
	_, ok := t[tagName]
	return ok
}

// ContainsAll checks if m is a subset of t.
func (t Tags) ContainsAll(m Tags) bool {
	for mTag := range m {
		_, ok := t[mTag]
		if !ok {
			return false
		}
	}
	return true
}

// GetValues returns all values of tags with the given key.
func (t Tags) GetValues(keyName string) []string {
	var values []string
	for tag := range t {
		if value, found := strings.CutPrefix(tag, keyName+"="); found {
			values = append(values, value)
		}
	}
	return values
}
