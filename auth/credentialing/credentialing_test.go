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

package credentialing_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/openpcc/openpcc/auth/credentialing"
	"github.com/stretchr/testify/require"
)

func TestCredentials(t *testing.T) {
	testCases := []struct {
		name       string
		creds      credentialing.Credentials
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "valid_credentials",
			creds: credentialing.Credentials{
				Models: []string{"llama3.2:1b", "qwen2:1.5b-instruct", "gemma3:1b"},
			},
			wantErr: false,
		},
		{
			name: "invalid_credentials_non_ascii_characters",
			creds: credentialing.Credentials{
				Models: []string{"llama3.2:1b", "invalidmodel😈1:1.5b"},
			},
			wantErr:    true,
			wantErrMsg: "contains non-ascii characters",
		},
		{
			name: "invalid_credentials_non_writable_ascii_chars",
			creds: credentialing.Credentials{
				Models: []string{"llama3.2:1b", "invalid\tmodel", "qwen2:1.5b-instruct", "gemma3:1b"},
			},
			wantErr:    true,
			wantErrMsg: "contains non-ascii characters",
		},
		{
			name: "invalid_credentials_empty_string",
			creds: credentialing.Credentials{
				Models: []string{"llama3.2:1b", "", "qwen2:1.5b-instruct", "gemma3:1b"},
			},
			wantErr:    true,
			wantErrMsg: "length must be greater than 0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			credProto, err := tc.creds.MarshalProto()
			if tc.wantErr {
				require.Error(t, err)
				require.True(t, strings.Contains(err.Error(), tc.wantErrMsg))
			} else {
				require.NoError(t, err)
				newCred := credentialing.Credentials{}
				err = newCred.UnmarshalProto(credProto)
				require.NoError(t, err)
				sort.Strings(tc.creds.Models)
				require.Equal(t, tc.creds.Models, newCred.Models)
			}
		})
	}
}
