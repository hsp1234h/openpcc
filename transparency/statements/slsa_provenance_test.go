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

package statements_test

import (
	"encoding/json"
	"testing"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsacommon "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/transparency"
	"github.com/openpcc/openpcc/transparency/statements"
	"github.com/stretchr/testify/require"
)

func TestSLSA02Provenance(t *testing.T) {
	newStatement := func() *transparency.Statement {
		// example taken from
		// https://github.com/slsa-framework/slsa-github-generator/blob/main/internal/builders/generic/README.md
		return &transparency.Statement{
			Subject: []transparency.StatementSubject{
				{
					Name: "ghcr.io/ianlewis/actions-test",
					Digest: map[string]string{
						"sha256": "8ae83e5b11e4cc8257f5f4d1023081ba1c72e8e60e8ed6cacd0d53a4ca2d142b",
					},
				},
			},
			PredicateType: "https://slsa.dev/provenance/v0.2",
			Predicate: map[string]any{
				"builder": map[string]any{
					"id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.2.2",
				},
				"buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
				"invocation": map[string]any{
					"configSource": map[string]any{
						"uri": "git+https://github.com/ianlewis/actions-test@refs/heads/main.git",
						"digest": map[string]any{
							"sha1": "e491e4b2ce5bc76fb103729b61b04d3c46d8a192",
						},
						"entryPoint": ".github/workflows/generic-container.yml",
					},
					"parameters": map[string]any{},
					"environment": map[string]any{
						"github_actor":               "ianlewis",
						"github_actor_id":            "49289",
						"github_base_ref":            "",
						"github_event_name":          "push",
						"github_event_payload":       map[string]any{},
						"github_head_ref":            "",
						"github_ref":                 "refs/tags/v0.0.9",
						"github_ref_type":            "tag",
						"github_repository_id":       "474793590",
						"github_repository_owner":    "ianlewis",
						"github_repository_owner_id": "49289",
						"github_run_attempt":         "1",
						"github_run_id":              "2556669934",
						"github_run_number":          "12",
						"github_sha1":                "e491e4b2ce5bc76fb103729b61b04d3c46d8a192",
					},
				},
			},
		}
	}

	t.Run("ok, to and from statement", func(t *testing.T) {
		slsaStatement := &intoto.ProvenanceStatementSLSA02{
			//nolint:staticcheck
			StatementHeader: intoto.StatementHeader{
				//nolint:staticcheck
				Subject: []intoto.Subject{
					{
						Name: "ghcr.io/ianlewis/actions-test",
						Digest: map[string]string{
							"sha256": "8ae83e5b11e4cc8257f5f4d1023081ba1c72e8e60e8ed6cacd0d53a4ca2d142b",
						},
					},
				},
				PredicateType: "https://slsa.dev/provenance/v0.2",
			},
			Predicate: slsa02.ProvenancePredicate{
				Builder: slsacommon.ProvenanceBuilder{
					ID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.2.2",
				},
				BuildType: "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
				Invocation: slsa02.ProvenanceInvocation{
					ConfigSource: slsa02.ConfigSource{
						URI: "git+https://github.com/ianlewis/actions-test@refs/heads/main.git",
						Digest: map[string]string{
							"sha1": "e491e4b2ce5bc76fb103729b61b04d3c46d8a192",
						},
						EntryPoint: ".github/workflows/generic-container.yml",
					},
					Parameters: map[string]any{},
					Environment: map[string]any{
						"github_actor":               "ianlewis",
						"github_actor_id":            "49289",
						"github_base_ref":            "",
						"github_event_name":          "push",
						"github_event_payload":       map[string]any{},
						"github_head_ref":            "",
						"github_ref":                 "refs/tags/v0.0.9",
						"github_ref_type":            "tag",
						"github_repository_id":       "474793590",
						"github_repository_owner":    "ianlewis",
						"github_repository_owner_id": "49289",
						"github_run_attempt":         "1",
						"github_run_id":              "2556669934",
						"github_run_number":          "12",
						"github_sha1":                "e491e4b2ce5bc76fb103729b61b04d3c46d8a192",
					},
				},
			},
		}

		wantStatement := newStatement()

		gotStatement, err := statements.FromSLSA02ProvenanceStatement(slsaStatement)
		require.NoError(t, err)
		require.Equal(t, wantStatement, gotStatement)

		gotSLSAStatement, err := statements.ToSLSA02ProvenanceStatement(gotStatement)
		require.NoError(t, err)

		require.Equal(t, slsaStatement, gotSLSAStatement)
	})

	t.Run("ok, slsa predicate is sanitized", func(t *testing.T) {
		testFS := test.TextArchiveFS(t, "testdata/sanitize-slsa-0.2-predicate.txt")

		inputJSON := test.ReadFile(t, testFS, "input.json")
		outputJSON := test.ReadFile(t, testFS, "output.json")

		slsaStatement := &intoto.ProvenanceStatementSLSA02{
			//nolint:staticcheck
			StatementHeader: intoto.StatementHeader{
				//nolint:staticcheck
				Subject: []intoto.Subject{
					{
						Name: "ghcr.io/ianlewis/actions-test",
						Digest: map[string]string{
							"sha256": "8ae83e5b11e4cc8257f5f4d1023081ba1c72e8e60e8ed6cacd0d53a4ca2d142b",
						},
					},
				},
				PredicateType: "https://slsa.dev/provenance/v0.2",
			},
		}

		err := json.Unmarshal(inputJSON, &slsaStatement.Predicate)
		require.NoError(t, err)

		wantPredicate := map[string]any{}
		err = json.Unmarshal(outputJSON, &wantPredicate)
		require.NoError(t, err)

		got, err := statements.FromSLSA02ProvenanceStatement(slsaStatement)
		require.NoError(t, err)

		require.Equal(t, wantPredicate, got.Predicate)
	})

	t.Run("fail, from slsa2 provenance statement, invalid predicate type", func(t *testing.T) {
		p := &intoto.ProvenanceStatementSLSA02{
			//nolint:staticcheck
			StatementHeader: intoto.StatementHeader{
				PredicateType: "invalid",
			},
		}

		_, err := statements.FromSLSA02ProvenanceStatement(p)
		require.Error(t, err)
	})

	t.Run("fail, to slsa2 provenance statement, invalid predicate type", func(t *testing.T) {
		s := newStatement()
		s.PredicateType = "invalid"

		_, err := statements.ToSLSA02ProvenanceStatement(s)
		require.Error(t, err)
	})
}
