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

package httpfmt_test

import (
	"net/http"
	"testing"

	"github.com/openpcc/openpcc/httpfmt"
	"github.com/stretchr/testify/require"
)

func TestFullCopyWorks(t *testing.T) {
	source := http.Header{}
	source.Add("foo", "bar")
	source.Add("baz", "quux")

	dest := http.Header{}
	httpfmt.CopyHeaders(source, dest)

	require.Equal(t, source, dest)
}

func TestExclusionWorksButYouMustCanonicalize(t *testing.T) {
	source := http.Header{}
	source.Add("foo", "bar")
	source.Add("baz", "quux")

	dest := http.Header{}
	httpfmt.CopyHeaders(source, dest, "Foo")

	require.Equal(t, 1, len(dest))
	require.Equal(t, "quux", dest.Get("Baz"))
}

func TestExclusionWorksOnRepeatedHeaders(t *testing.T) {
	source := http.Header{}
	source.Add("foo", "bar")
	source.Add("foo", "baz")

	dest := http.Header{}
	httpfmt.CopyHeaders(source, dest, "Foo")

	require.Equal(t, 0, len(dest))
}
