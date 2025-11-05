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

package cmdline

import (
	"errors"
	"fmt"
	"strings"
)

// Parse parses a kernel command line string into a map of key-value pairs.
//
// Examples:
//   - "root=/dev/sda1 quiet" -> {"root": "/dev/sda1", "quiet": ""}
func Parse(cmdline string) (map[string]string, error) {
	result := make(map[string]string)

	// State machine for parsing
	var (
		inEscape     = false
		currentKey   = ""
		currentValue = ""
		state        = "key"
	)

	cmdline = strings.TrimSpace(cmdline)

	for i, r := range cmdline {
		switch {
		case inEscape:
			if state != "value_quoted" {
				return nil, fmt.Errorf("escape sequence not allowed outside quoted values at position %d", i)
			}
			currentValue += string(r)
			inEscape = false

		case r == '\\':
			if state != "value_quoted" {
				return nil, fmt.Errorf("escape sequence not allowed outside quoted values at position %d", i)
			}
			inEscape = true

		case r == '"':
			switch state {
			case "key":
				return nil, fmt.Errorf("quotes not allowed in keys at position %d", i)
			case "value":
				state = "value_quoted"
			case "value_quoted":
				state = "value"
			default:
			}

		case r == '=' && state == "key":
			if currentKey == "" {
				return nil, fmt.Errorf("empty key before '=' at position %d", i)
			}
			state = "value"

		case (r == ' ' || r == '\t') && state != "value_quoted":
			if state == "key" && currentKey != "" {
				result[currentKey] = ""
				currentKey = ""
			} else if state == "value" {
				result[currentKey] = currentValue
				currentKey = ""
				currentValue = ""
				state = "key"
			}

		case r == ' ' || r == '\t':
			if state == "key" {
				return nil, fmt.Errorf("spaces not allowed in keys at position %d", i)
			}
			currentValue += string(r)

		default:
			if state == "key" {
				currentKey += string(r)
			} else {
				currentValue += string(r)
			}
		}
	}

	if inEscape {
		return nil, errors.New("unterminated escape sequence at end of string")
	}
	if state == "value_quoted" {
		return nil, errors.New("unterminated quoted string")
	}

	if state == "key" && currentKey != "" {
		result[currentKey] = ""
	} else if currentKey != "" {
		result[currentKey] = currentValue
	}

	return result, nil
}
