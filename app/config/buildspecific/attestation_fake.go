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
//go:build include_fake_attestation

package buildspecific

import (
	"github.com/openpcc/openpcc"
	"github.com/openpcc/openpcc/app/config"
)

func FakeAttestationSecretEnvMapping[T any](mappings map[string]config.EnvMapping[T], mapFunc func(cfg *T, val string) error) {
	mappings["FAKE_ATTESTATION_SECRET"] = config.EnvMapping[T]{
		Required: false,
		Func:     mapFunc,
	}
}

func AppendFakeAttestationSecretOption(opts []openpcc.Option, secret string) []openpcc.Option {
	return append(opts, openpcc.WithFakeAttestationSecret(secret))
}
