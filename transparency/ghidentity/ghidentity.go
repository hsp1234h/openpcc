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

package ghidentity

import "github.com/openpcc/openpcc/transparency"

// Policy returns an identity policy that verifies sigstore bundles
// are signed using our trusted Github Identity.
func Policy() transparency.IdentityPolicy {
	return transparency.IdentityPolicy{
		// Allow bundles signed by github actions from the T repository.
		OIDCSubjectRegex: "^https://github.com/confidentsecurity/T/.github/workflows.*",
		OIDCIssuerRegex:  "https://token.actions.githubusercontent.com",
	}
}
