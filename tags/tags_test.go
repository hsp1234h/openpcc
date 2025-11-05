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

package tags_test

import (
	"strings"
	"testing"

	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/tags"
	"github.com/stretchr/testify/require"
)

func TestTagsFromSlice(t *testing.T) {
	tests := map[string]struct {
		in   []string
		want tags.Tags
	}{
		"ok, nil": {
			in:   nil,
			want: make(tags.Tags),
		},
		"ok, empty": {
			in:   []string{},
			want: make(tags.Tags),
		},
		"ok, single": {
			in: []string{"v1.0"},
			want: tags.Tags{
				"v1.0": {},
			},
		},
		"ok, multiple unique": {
			in: []string{"v1.0", "v2.0", "v3.0"},
			want: tags.Tags{
				"v1.0": {},
				"v2.0": {},
				"v3.0": {},
			},
		},
		"ok, multiple duplicates": {
			in: []string{"v1.0", "v2.0", "v2.0"},
			want: tags.Tags{
				"v1.0": {},
				"v2.0": {},
			},
		},
		"ok, max length": {
			in: []string{strings.Repeat("a", 512)},
			want: tags.Tags{
				strings.Repeat("a", 512): {},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := tags.FromSlice(tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	failTests := map[string][]string{
		"fail, over max length": {
			strings.Repeat("a", 513),
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := tags.FromSlice(tc)
			require.Error(t, err)
		})
	}
}

func TestTagsContainsAll(t *testing.T) {
	tests := map[string]struct {
		tags     tags.Tags
		input    tags.Tags
		contains bool
	}{
		"true, empty tag set contains itself": {
			tags:     test.Must(tags.FromSlice([]string{})),
			input:    test.Must(tags.FromSlice([]string{})),
			contains: true,
		},
		"true, contains empty tag set": {
			tags:     test.Must(tags.FromSlice([]string{"v1.0"})),
			input:    test.Must(tags.FromSlice([]string{})),
			contains: true,
		},
		"true, contains one": {
			tags:     test.Must(tags.FromSlice([]string{"v1.0", "llm", "compute"})),
			input:    test.Must(tags.FromSlice([]string{"v1.0"})),
			contains: true,
		},
		"true, contains all": {
			tags:     test.Must(tags.FromSlice([]string{"v1.0", "llm", "compute"})),
			input:    test.Must(tags.FromSlice([]string{"v1.0", "llm", "compute"})),
			contains: true,
		},
		"false, empty tag set does not contain anything": {
			tags:     test.Must(tags.FromSlice([]string{})),
			input:    test.Must(tags.FromSlice([]string{"v1.0"})),
			contains: false,
		},
		"false, contains none": {
			tags:     test.Must(tags.FromSlice([]string{"v1.0", "llm", "compute"})),
			input:    test.Must(tags.FromSlice([]string{"v2.0", "weather", "not-compute"})),
			contains: false,
		},
		"false, contains all but one": {
			tags:     test.Must(tags.FromSlice([]string{"v1.0", "llm", "compute"})),
			input:    test.Must(tags.FromSlice([]string{"v1.0", "llm", "BETA"})),
			contains: false,
		},
		"false, contains all but has one extra": {
			tags:     test.Must(tags.FromSlice([]string{"v1.0", "llm", "compute"})),
			input:    test.Must(tags.FromSlice([]string{"v1.0", "llm", "compute", "BETA"})),
			contains: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tc.tags.ContainsAll(tc.input)
			require.Equal(t, tc.contains, got)
		})
	}
}

func TestTagsModify(t *testing.T) {
	tests := map[string]struct {
		tags     tags.Tags
		modifier func(t *testing.T, input tags.Tags)
		expected tags.Tags
	}{
		"ok, add tag": {
			tags: test.Must(tags.FromSlice([]string{"v1.0", "llm"})),
			modifier: func(t *testing.T, input tags.Tags) {
				test.Must(t, input.AddTag("compute"))
			},
			expected: test.Must(tags.FromSlice([]string{"v1.0", "llm", "compute"})),
		},
		"ok, add tag pair": {
			tags: test.Must(tags.FromSlice([]string{"v1.0", "llm"})),
			modifier: func(t *testing.T, input tags.Tags) {
				test.Must(t, input.AddTagPair("model", "llama3.2:1b"))
			},
			expected: test.Must(tags.FromSlice([]string{"v1.0", "llm", "model=llama3.2:1b"})),
		},
		"ok, remove key": {
			tags: test.Must(tags.FromSlice([]string{"v1.0", "llm", "model=llama3.2:1b"})),
			modifier: func(_ *testing.T, input tags.Tags) {
				input.RemoveKey("model")
			},
			expected: test.Must(tags.FromSlice([]string{"v1.0", "llm"})),
		},
		"ok, remove key multiple entries": {
			tags: test.Must(tags.FromSlice([]string{"v1.0", "llm", "model=llama3.2:1b", "model=qwen2:1.5b-instruct"})),
			modifier: func(_ *testing.T, input tags.Tags) {
				input.RemoveKey("model")
			},
			expected: test.Must(tags.FromSlice([]string{"v1.0", "llm"})),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tc.modifier(t, tc.tags)
			require.Equal(t, tc.tags, tc.expected)
		})
	}

	failTests := map[string]struct {
		tags     tags.Tags
		modifier func(t *testing.T, input tags.Tags) error
	}{
		"fail, attempt to add key with '='": {
			tags: test.Must(tags.FromSlice([]string{"v1.0", "llm"})),
			modifier: func(t *testing.T, input tags.Tags) error {
				return input.AddTagPair("model=llama3.2", "1.b")
			},
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := tc.modifier(t, tc.tags)
			require.Error(t, err)
		})
	}
}

func TestTagsGetValues(t *testing.T) {
	tags := tags.Tags{"foo=bar": {}, "foo=baz": {}, "qux=": {}, "other=value": {}}
	t.Run("found multiple", func(t *testing.T) {
		vals := tags.GetValues("foo")
		require.Len(t, vals, 2)
		require.Contains(t, vals, "bar")
		require.Contains(t, vals, "baz")
	})
	t.Run("found single empty", func(t *testing.T) {
		vals := tags.GetValues("qux")
		require.Equal(t, []string{""}, vals)
	})
	t.Run("found single", func(t *testing.T) {
		vals := tags.GetValues("other")
		require.Equal(t, []string{"value"}, vals)
	})
	t.Run("not found", func(t *testing.T) {
		vals := tags.GetValues("missing")
		require.Empty(t, vals)
	})
}
