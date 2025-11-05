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

package hpke

import (
	"fmt"
	"runtime/debug"
)

// versionChecked is the version this package was last manually inspected for.
//
// Since this package is based on code in the github.com/cloudflare/circl/hpke,
// we should make an effort to keep this in sync. Especially when it concerns
// security updates.
//
// When a new version of circl is available, we should do the following:
//  1. Confirm there are changes to github.com/cloudflare/circl/hpke.
//  2. If there are no changes, bump versionChecked to the new version.
//  3. If there are changes:
//     3.1. Check if they impact the code in this package.
//     3.2. Make the necessary adjustments.
//     3.3. Bump versionChecked to match the new version of circl.
const (
	versionChecked = "v1.6.1"
	circlPackage   = "github.com/cloudflare/circl"
)

func init() {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		panic("failed to read build info")
	}

	for _, dep := range buildInfo.Deps {
		if dep.Path == "github.com/cloudflare/circl" {
			if dep.Version != versionChecked {
				msg := fmt.Sprintf(`using version %s@%v.
internal/tpm/hpke was last checked for %v.
Make sure it wasn't impacted by any changes.
`, circlPackage, dep.Version, versionChecked)
				panic(msg)
			}
		}
	}
}
