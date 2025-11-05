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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
		wantErr  bool
	}{
		{
			name:  "typical kernel cmdline",
			input: "BOOT_IMAGE=/boot/vmlinuz root=UUID=12345 ro quiet splash",
			expected: map[string]string{
				"BOOT_IMAGE": "/boot/vmlinuz",
				"root":       "UUID=12345",
				"ro":         "",
				"quiet":      "",
				"splash":     "",
			},
			wantErr: false,
		},
		{
			name:  "kernel cmdline with quoted initrd",
			input: "root=/dev/sda1 initrd=\"/boot/initrd with spaces.img\" quiet",
			expected: map[string]string{
				"root":   "/dev/sda1",
				"initrd": "/boot/initrd with spaces.img",
				"quiet":  "",
			},
			wantErr: false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: map[string]string{},
			wantErr:  false,
		},
		{
			name:     "single key without value",
			input:    "quiet",
			expected: map[string]string{"quiet": ""},
			wantErr:  false,
		},
		{
			name:     "single key-value pair",
			input:    "root=/dev/sda1",
			expected: map[string]string{"root": "/dev/sda1"},
			wantErr:  false,
		},
		{
			name:     "multiple parameters",
			input:    "root=/dev/sda1 quiet splash",
			expected: map[string]string{"root": "/dev/sda1", "quiet": "", "splash": ""},
			wantErr:  false,
		},
		{
			name:     "quoted value with spaces",
			input:    "param=\"value with spaces\"",
			expected: map[string]string{"param": "value with spaces"},
			wantErr:  false,
		},
		{
			name:     "quoted value with escaped quotes",
			input:    "param=\"value with \\\"escaped\\\" quotes\"",
			expected: map[string]string{"param": "value with \"escaped\" quotes"},
			wantErr:  false,
		},
		{
			name:     "mixed quoted and unquoted",
			input:    "root=/dev/sda1 title=\"My Boot Menu\" quiet",
			expected: map[string]string{"root": "/dev/sda1", "title": "My Boot Menu", "quiet": ""},
			wantErr:  false,
		},
		{
			name:     "empty quoted value",
			input:    "param=\"\"",
			expected: map[string]string{"param": ""},
			wantErr:  false,
		},
		{
			name:     "quoted value with tabs and spaces",
			input:    "param=\"value with\ttabs and  spaces\"",
			expected: map[string]string{"param": "value with\ttabs and  spaces"},
			wantErr:  false,
		},
		{
			name:     "multiple spaces between parameters",
			input:    "root=/dev/sda1    quiet     splash",
			expected: map[string]string{"root": "/dev/sda1", "quiet": "", "splash": ""},
			wantErr:  false,
		},
		{
			name:     "parameter with equals in quoted value",
			input:    "param=\"value=with=equals\"",
			expected: map[string]string{"param": "value=with=equals"},
			wantErr:  false,
		},
		{
			name:     "parameter with whitespaces",
			input:    "  root=/dev/sda1   quiet   ",
			expected: map[string]string{"root": "/dev/sda1", "quiet": ""},
			wantErr:  false,
		},
		// Error cases
		{
			name:    "unterminated quote",
			input:   "param=\"unterminated",
			wantErr: true,
		},
		{
			name:    "quote in key",
			input:   "param\"key=value",
			wantErr: true,
		},
		{
			name:    "empty key",
			input:   "=value",
			wantErr: true,
		},
		{
			name:    "unterminated escape",
			input:   "param=\"value\\",
			wantErr: true,
		},
		{
			name:    "escape outside quotes",
			input:   "param=value\\nmore",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Parse(tt.input)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestParse_RealCase(t *testing.T) {
	cmdline := "kernel_cmdline: /vmlinuz-6.8.0-1033-gcp ro rd.dm=1 systemd.verity=1 lsm=lockdown,capability,landlock,yama,selinux,integrity apparmor=0 selinux=1 root=/dev/mapper/verity-root confsec.root=0b068427716acce1c0aa02cf24fda96691957c631235b513e53e6e75ceaf0e5d confsec.efi=74f31994190d2d0c51f1e4960e15a2c82ae1b094b38ce8925a3fffceeace60c5 confsec.crypt.git=f9256d6b487b0fdfc384b2215639ea2f69012480 confsec.crypt.build_id=88f433a1-76fd-48a9-a8f4-ea0dd5c17c9c confsec.crypt.hardening_scope=2 confsec.crypt.debug_scope=1 confsec.crypt.optimize_disk=true confsec.opt=719e825aa0568584c88ea9b3620bd72e871d347739cab49c926ec63dbe236f39 confsec.compute.git=e3228d4903574f0be1f398c7d5bc8419f924e13b confsec.compute.build_id=d2d2cd18-c117-4d4d-a80c-8ef177e36620 confsec.compute.hardening_scope=2 confsec.compute.debug_scope=1 confsec.compute.optimize_disk=true console=ttyS0,115200\x00"
	result, err := Parse(cmdline)
	require.NoError(t, err)
	require.Equal(t, "0b068427716acce1c0aa02cf24fda96691957c631235b513e53e6e75ceaf0e5d", result["confsec.root"])
}
