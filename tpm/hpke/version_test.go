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
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCirclVersionCheck(t *testing.T) {
	// We also do this at runtime in `version.go`, but debug.ReadBuildInfo()
	// does not return module information in tests.
	//
	// This test allows us to fail early in PR's.
	modules, err := ModuleVersionFromGoMod("../../go.mod")
	require.NoError(t, err)

	version, ok := modules[circlPackage]
	require.True(t, ok, "circl package not found in go modules")

	msg := fmt.Sprintf(`using version %s@%v.
internal/tpm/hpke was last checked for %v.
Make sure it wasn't impacted by any changes.
`, circlPackage, version, versionChecked)

	require.Equal(t, versionChecked, version, msg)
}

func ModuleVersionFromGoMod(filename string) (map[string]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	versions := make(map[string]string)
	lines := strings.Split(string(data), "\n")

	inMultiLineRequire := false
	for _, line := range lines {
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "require (") {
			inMultiLineRequire = true
			continue
		}

		if inMultiLineRequire && strings.HasPrefix(line, ")") {
			inMultiLineRequire = false
			continue
		}

		// single line require
		if strings.HasPrefix("require", line) {
			fields := strings.Fields(line)
			if len(fields) != 3 {
				continue
			}

			module := fields[1]
			version := fields[2]
			versions[module] = version
			continue
		}

		// multi line require
		if inMultiLineRequire {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}

			module := fields[0]
			version := fields[1]
			versions[module] = version
			continue
		}
	}

	return versions, nil
}
