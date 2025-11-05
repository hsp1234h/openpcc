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

package transparency_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/openpcc/openpcc/transparency"
	"github.com/stretchr/testify/require"
)

func TestStatementValidate(t *testing.T) {
	validTests := map[string]func(*transparency.Statement){
		"ok, single subject with predicate": func(s *transparency.Statement) {
			// noop, use the default statement.
		},
		"ok, nil predicate": func(s *transparency.Statement) {
			s.Predicate = nil
		},
		"ok, multiple subjects": func(s *transparency.Statement) {
			s.Subject = nil
			for i := range 10 {
				name := fmt.Sprintf("subject-%d", i)
				digest := sha256.Sum256([]byte(name))
				s.Subject = append(s.Subject, transparency.StatementSubject{
					Name: name,
					Digest: map[string]string{
						"sha256": hex.EncodeToString(digest[:]),
					},
				})
			}
		},
	}

	for name, modFunc := range validTests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := newGreetingStatement(t, "hello world!")
			modFunc(s)

			err := s.Validate()
			require.NoError(t, err)
		})
	}

	invalidTests := map[string]func(*transparency.Statement) *transparency.Statement{
		"fail, nil statement": func(s *transparency.Statement) *transparency.Statement {
			return nil
		},
		"fail, statement with nil subject": func(s *transparency.Statement) *transparency.Statement {
			s.Subject = nil
			return s
		},
		"fail, statement with a nil digest": func(s *transparency.Statement) *transparency.Statement {
			s.Subject[0] = transparency.StatementSubject{
				Name:   "greeting",
				Digest: nil,
			}
			return s
		},
		"fail, sha256 digest empty": func(s *transparency.Statement) *transparency.Statement {
			s.Subject[0] = transparency.StatementSubject{
				Name: "greeting",
				Digest: map[string]string{
					"sha256": "",
				},
			}
			return s
		},
		"fail, non-hex encoded sha256 in digest": func(s *transparency.Statement) *transparency.Statement {
			s.Subject[0] = transparency.StatementSubject{
				Name: "greeting",
				Digest: map[string]string{
					"sha256": strings.Repeat("#", 64),
				},
			}
			return s
		},
		"fail, hex encoded digest long": func(s *transparency.Statement) *transparency.Statement {
			s.Subject[0] = transparency.StatementSubject{
				Name: "greeting",
				Digest: map[string]string{
					"sha256": strings.Repeat("0", 66),
				},
			}
			return s
		},
		"fail, hex encoded digest short": func(s *transparency.Statement) *transparency.Statement {
			s.Subject[0] = transparency.StatementSubject{
				Name: "greeting",
				Digest: map[string]string{
					"sha256": strings.Repeat("0", 62),
				},
			}
			return s
		},
		"fail, empty predicate type": func(s *transparency.Statement) *transparency.Statement {
			s.PredicateType = ""
			return s
		},
		"fail, non-url predicate type": func(s *transparency.Statement) *transparency.Statement {
			s.PredicateType = "\t"
			return s
		},
		"fail, predicate type is missing scheme": func(s *transparency.Statement) *transparency.Statement {
			s.PredicateType = "example.com/path"
			return s
		},
		"fail, predicate type is missing host": func(s *transparency.Statement) *transparency.Statement {
			s.PredicateType = "http:///path"
			return s
		},
	}

	for name, modFunc := range invalidTests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := newGreetingStatement(t, "hello world!")
			s = modFunc(s)

			err := s.Validate()
			require.Error(t, err)
		})
	}
}

func newGreetingStatement(_ *testing.T, greeting string) *transparency.Statement {
	// hashes of the subjects will be part of the sigstore bundle.
	subjects := map[string][]byte{
		"greeting": []byte(greeting),
	}

	// predicate will be included in the transparency log.
	predicate := map[string]any{
		"originalGreeting": base64.StdEncoding.EncodeToString([]byte(greeting)),
		"source":           "a Go test case",
	}

	return transparency.NewStatement(subjects, "https://example.com/v1/greeting+plain", predicate)
}

// nolint: unparam
func newConversationStatement(t *testing.T, greeting, goodbye string) *transparency.Statement {
	t.Helper()

	// hashes of the subjects will be part of the sigstore bundle.
	subjects := map[string][]byte{
		"greeting": []byte(greeting),
		"goodbye":  []byte(goodbye),
	}
	// predicate will be stored in the sigstore bundle as-is.
	predicate := map[string]any{
		"originalGreeting": base64.StdEncoding.EncodeToString([]byte(greeting)),
		"originalGoodbye":  base64.StdEncoding.EncodeToString([]byte(goodbye)),
		"source":           "a Go test case",
	}

	return transparency.NewStatement(subjects, "https://example.com/v1/conversation+plain", predicate)
}
