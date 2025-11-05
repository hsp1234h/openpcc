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

package statements

import (
	"testing"

	"github.com/openpcc/openpcc/transparency"
	"github.com/stretchr/testify/require"
)

func TestFromImageManifest(t *testing.T) {
	tests := []struct {
		name           string
		manifest       *ImageManifest
		wantErr        bool
		errContains    string
		checkSubject   bool
		checkPredicate bool
	}{
		{
			name: "valid manifest",
			manifest: &ImageManifest{
				Name:          "test-build",
				BuilderType:   "packer",
				BuildTime:     1640995200,
				ArtifactID:    "ami-1234567890abcdef0",
				PackerRunUUID: "test-uuid",
				CustomData: &BuildCustomData{
					BuildEnv: map[string]string{
						"PACKER_VERSION": "1.7.0",
					},
					GPTLayout: "standard",
				},
			},
			wantErr:        false,
			checkSubject:   true,
			checkPredicate: true,
		},
		{
			name: "valid manifest with kernel cmdlines",
			manifest: &ImageManifest{
				Name:       "kernel-build",
				ArtifactID: "ami-kernel",
				CustomData: &BuildCustomData{
					KernelCmdlines: []KernelCmdline{
						{
							Root:        "/dev/sda1",
							ConfsecRoot: "/secure",
							LSM:         "apparmor",
							AppArmor:    "enforce",
							SELinux:     "disabled",
							Console:     "ttyS0",
						},
					},
				},
			},
			wantErr:        false,
			checkSubject:   true,
			checkPredicate: true,
		},
		{
			name:        "nil custom data",
			manifest:    &ImageManifest{},
			wantErr:     true,
			errContains: "no custom data in image manifest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statement, err := FromImageManifest(tt.manifest)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
				require.Nil(t, statement)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, statement)

			require.Equal(t, ImageManifestPredicateType, statement.PredicateType)

			if tt.checkSubject {
				require.Len(t, statement.Subject, 1)
				subject := statement.Subject[0]
				require.Equal(t, "image-manifest", subject.Name)
				require.NotEmpty(t, subject.Digest["sha256"])
				require.Len(t, subject.Digest["sha256"], 64) // SHA256 hex is 64 chars
			}

			if tt.checkPredicate {
				require.Contains(t, statement.Predicate, "imageManifest")
				manifestBase64, ok := statement.Predicate["imageManifest"].(string)
				require.True(t, ok, "imageManifest should be a string")
				require.NotEmpty(t, manifestBase64)
			}

			err = statement.Validate()
			require.NoError(t, err)
		})
	}
}

type mockTransparencyVerifier struct {
	statement *transparency.Statement
	metadata  transparency.BundleMetadata
	err       error
}

func (m *mockTransparencyVerifier) VerifyStatementWithProcessor(b []byte, processor transparency.PredicateProcessor, identity transparency.IdentityPolicy) (*transparency.Statement, transparency.BundleMetadata, error) {
	if m.err != nil {
		return nil, transparency.BundleMetadata{}, m.err
	}

	if m.statement != nil {
		_, err := processor(m.statement)
		if err != nil {
			return nil, transparency.BundleMetadata{}, err
		}
	}

	return m.statement, m.metadata, nil
}

func TestVerifyImageManifestBundle(t *testing.T) {
	tests := []struct {
		name        string
		verifier    *mockTransparencyVerifier
		wantErr     bool
		errContains string
	}{
		{
			name: "valid manifest",
			verifier: &mockTransparencyVerifier{
				statement: func() *transparency.Statement {
					manifest := &ImageManifest{
						Name:       "test-build",
						ArtifactID: "ami-1234567890abcdef0",
						CustomData: &BuildCustomData{
							GPTLayout: "standard",
						},
					}
					stmt, _ := FromImageManifest(manifest)
					return stmt
				}(),
				metadata: transparency.BundleMetadata{},
			},
			wantErr: false,
		},
		{
			name: "manifest with nil custom data",
			verifier: &mockTransparencyVerifier{
				statement: &transparency.Statement{
					PredicateType: ImageManifestPredicateType,
					Subject: []transparency.StatementSubject{
						{
							Name:   "image-manifest",
							Digest: map[string]string{"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
						},
					},
					Predicate: map[string]any{
						"imageManifest": "e30=", // base64 encoded {}
					},
				},
				metadata: transparency.BundleMetadata{},
			},
			wantErr:     true,
			errContains: "no custom data in image manifest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statement, metadata, err := VerifyImageManifestBundle([]byte("test-bundle"), tt.verifier, transparency.IdentityPolicy{})

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, statement)
			require.Equal(t, tt.verifier.metadata, metadata)
		})
	}
}

func TestToImageManifest(t *testing.T) {
	tests := []struct {
		name        string
		statement   *transparency.Statement
		wantErr     bool
		errContains string
		checkResult bool
	}{
		{
			name: "valid statement with correct predicate type",
			statement: func() *transparency.Statement {
				manifest := &ImageManifest{
					Name:          "test-build",
					BuilderType:   "packer",
					BuildTime:     1640995200,
					ArtifactID:    "ami-1234567890abcdef0",
					PackerRunUUID: "test-uuid",
					CustomData: &BuildCustomData{
						BuildEnv: map[string]string{
							"PACKER_VERSION": "1.7.0",
						},
						GPTLayout: "standard",
					},
				}
				stmt, _ := FromImageManifest(manifest)
				return stmt
			}(),
			wantErr:     false,
			checkResult: true,
		},
		{
			name: "invalid predicate type",
			statement: &transparency.Statement{
				PredicateType: "https://example.com/wrong-type",
				Subject: []transparency.StatementSubject{
					{
						Name:   "test",
						Digest: map[string]string{"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
					},
				},
				Predicate: map[string]any{
					"imageManifest": "dGVzdA==", // base64 "test"
				},
			},
			wantErr:     true,
			errContains: "invalid predicate type",
		},
		{
			name: "statement with invalid subject (empty)",
			statement: &transparency.Statement{
				PredicateType: ImageManifestPredicateType,
				Subject:       []transparency.StatementSubject{},
				Predicate: map[string]any{
					"imageManifest": "dGVzdA==",
				},
			},
			wantErr:     true,
			errContains: "invalid statement",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest, err := ToImageManifest(tt.statement)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
				require.Nil(t, manifest)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, manifest)

			if tt.checkResult {
				require.NotEmpty(t, manifest.CustomData)
				require.Equal(t, "test-build", manifest.Name)
				require.Equal(t, "packer", manifest.BuilderType)
				require.Equal(t, int64(1640995200), manifest.BuildTime)
				require.Equal(t, "ami-1234567890abcdef0", manifest.ArtifactID)
				require.Equal(t, "test-uuid", manifest.PackerRunUUID)
				require.Equal(t, "1.7.0", manifest.CustomData.BuildEnv["PACKER_VERSION"])
				require.Equal(t, "standard", manifest.CustomData.GPTLayout)
			}
		})
	}
}
