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

package httpfmt

import (
	"net/http"
	"slices"
)

// CopyHeaders copies headers from one http.Header to another, except for those named in skipNames, which must be canonicalized.
func CopyHeaders(from, to http.Header, skipNames ...string) {
	for name, values := range from {
		if slices.Contains(skipNames, name) {
			continue
		}

		for _, value := range values {
			to.Add(name, value)
		}
	}
}

// MakeAuthHeaderValue prefixes an auth secret with 'Bearer ' to be used within the
// Authorization header of an HTTP request.
func MakeAuthHeaderValue(secret string) string {
	return "Bearer " + secret
}
