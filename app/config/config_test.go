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

package config_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/openpcc/openpcc/app/config"
	"github.com/stretchr/testify/require"
)

type loadableConfig struct {
	StaysUntouched    string
	SourcedFromYAML   string `yaml:"sourced_from_yaml"`
	SourcedFromEnv    string
	fakeValidationErr error
}

func (c *loadableConfig) IsValid() error {
	return c.fakeValidationErr
}

func TestLoad(t *testing.T) {
	load := func(fakeValidationErr error) (*loadableConfig, error) {
		mapping := map[string]config.EnvMapping[loadableConfig]{
			"SOURCED_FROM_ENV": {
				Required: true,
				Func: func(cfg *loadableConfig, val string) error {
					cfg.SourcedFromEnv = val
					return nil
				},
			},
		}

		cfg := &loadableConfig{
			StaysUntouched:    "a",
			fakeValidationErr: fakeValidationErr,
		}

		err := config.Load(cfg, "./testdata/config.yaml", mapping)
		return cfg, err
	}

	t.Run("ok, valid config", func(t *testing.T) {
		setupEnviron(t, map[string]string{
			"SOURCED_FROM_ENV": "c",
		})

		got, err := load(nil)
		require.NoError(t, err)

		want := &loadableConfig{
			StaysUntouched:    "a",
			SourcedFromYAML:   "b",
			SourcedFromEnv:    "c",
			fakeValidationErr: nil,
		}

		require.Equal(t, want, got)
	})

	t.Run("ok, invalid config", func(t *testing.T) {
		setupEnviron(t, map[string]string{
			"SOURCED_FROM_ENV": "c",
		})

		// inject a validation error that we expect to be returned
		var validationErr = errors.New("validation error")

		_, err := load(validationErr)
		require.Error(t, err)
		require.ErrorIs(t, err, validationErr)
	})
}

func TestMergeYAML(t *testing.T) {
	type testConfig struct {
		StringVal string  `yaml:"string_val"`
		IntVal    int     `yaml:"int_val"`
		BoolVal   bool    `yaml:"bool_val"`
		FloatVal  float64 `yaml:"float_val"`
	}

	tests := map[string]struct {
		config  *testConfig
		environ map[string]string
		yamlSrc string
		want    *testConfig
	}{
		"ok, no yaml": {
			config: &testConfig{
				StringVal: "a",
				IntVal:    3485,
				BoolVal:   true,
				FloatVal:  123.456,
			},
			want: &testConfig{
				StringVal: "a",
				IntVal:    3485,
				BoolVal:   true,
				FloatVal:  123.456,
			},
		},
		"ok, yaml leaves unmentioned fields untouched": {
			config: &testConfig{
				StringVal: "a",
				IntVal:    3485,
				BoolVal:   true,
				FloatVal:  123.456,
			},
			yamlSrc: `string_val: b
int_val: 45678
`,
			want: &testConfig{
				StringVal: "b",
				IntVal:    45678,
				BoolVal:   true,
				FloatVal:  123.456,
			},
		},
		"ok, unknown fields in yaml are ignored": {
			config: &testConfig{
				StringVal: "a",
				IntVal:    3485,
				BoolVal:   true,
				FloatVal:  123.456,
			},
			yamlSrc: `unknown_field_1: b
unknown_field_2: 45678
`,
			want: &testConfig{
				StringVal: "a",
				IntVal:    3485,
				BoolVal:   true,
				FloatVal:  123.456,
			},
		},
		"ok, yaml overrides defaults": {
			config: &testConfig{
				StringVal: "a",
				IntVal:    3485,
				BoolVal:   true,
				FloatVal:  123.456,
			},
			yamlSrc: `string_val: b
int_val: 45678
bool_val: false
float_val: 456.123
`,
			want: &testConfig{
				StringVal: "b",
				IntVal:    45678,
				BoolVal:   false,
				FloatVal:  456.123,
			},
		},
		"ok, expand environment variable before parsing yaml": {
			config: &testConfig{},
			yamlSrc: `string_val: $STRING_VAL
int_val: $INT_VAL
bool_val: $BOOL_VAL
float_val: $FLOAT_VAL`,
			environ: map[string]string{
				"STRING_VAL": "b",
				"INT_VAL":    "45678",
				"BOOL_VAL":   "true",
				"FLOAT_VAL":  "456.123",
			},
			want: &testConfig{
				StringVal: "b",
				IntVal:    45678,
				BoolVal:   true,
				FloatVal:  456.123,
			},
		},
		"ok, expand environment variable before parsing yaml (curly brace syntax)": {
			config: &testConfig{},
			yamlSrc: `string_val: ${STRING_VAL}
int_val: ${INT_VAL}
bool_val: ${BOOL_VAL}
float_val: ${FLOAT_VAL}`,
			environ: map[string]string{
				"STRING_VAL": "b",
				"INT_VAL":    "45678",
				"BOOL_VAL":   "true",
				"FLOAT_VAL":  "456.123",
			},
			want: &testConfig{
				StringVal: "b",
				IntVal:    45678,
				BoolVal:   true,
				FloatVal:  456.123,
			},
		},
		"ok, expand missing environment variable with default value": {
			config: &testConfig{},
			yamlSrc: `string_val: ${STRING_VAL:-b}
int_val: ${INT_VAL:-45678}
bool_val: ${BOOL_VAL:-true}
float_val: ${FLOAT_VAL:-456.123}`,
			want: &testConfig{
				StringVal: "b",
				IntVal:    45678,
				BoolVal:   true,
				FloatVal:  456.123,
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// can't run these tests in parallel, they share the same environment.
			setupEnviron(t, tc.environ)

			got := tc.config
			err := config.MergeYAML(got, strings.NewReader(tc.yamlSrc))
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	t.Run("fail, environment variable missing", func(t *testing.T) {
		// this yaml template mentions an environment variable that isn't set.
		// This environment variable also doesn't have a default value,
		// so we assume the YAML author meant for it to be set and we return
		// an error.
		got := &testConfig{}
		yamlSrc := `string_val: $MISSING_STRING_VAL
int_val: $MISSING_INT_VAL
`

		err := config.MergeYAML(got, strings.NewReader(yamlSrc))
		require.Error(t, err)
		// ensure missing environment variables are mentioned in error message.
		require.Contains(t, err.Error(), "MISSING_STRING_VAL")
		require.Contains(t, err.Error(), "MISSING_INT_VAL")
	})
}

func TestMergeEnv(t *testing.T) {
	type testConfig struct {
		StringVal string
		IntVal    int
	}

	tests := map[string]struct {
		config  *testConfig
		environ map[string]string
		mapping map[string]config.EnvMapping[testConfig]
		want    *testConfig
	}{
		"ok, no environment": {
			config: &testConfig{
				StringVal: "a",
				IntVal:    123,
			},
			environ: map[string]string{},
			mapping: map[string]config.EnvMapping[testConfig]{},
			want: &testConfig{
				StringVal: "a",
				IntVal:    123,
			},
		},
		"ok, non-required mapping, variable provided": {
			config: &testConfig{
				StringVal: "a",
				IntVal:    123,
			},
			environ: map[string]string{
				"STRING_VAL": "b",
			},
			mapping: map[string]config.EnvMapping[testConfig]{
				"STRING_VAL": {
					Required: false,
					Func: func(cfg *testConfig, val string) error {
						cfg.StringVal = val
						return nil
					},
				},
			},
			want: &testConfig{
				StringVal: "b",
				IntVal:    123,
			},
		},
		"ok, non-required mapping, variable not provided": {
			config: &testConfig{
				StringVal: "a",
				IntVal:    123,
			},
			environ: map[string]string{}, // STRING_VAL is not provided
			mapping: map[string]config.EnvMapping[testConfig]{
				"STRING_VAL": {
					Required: false,
					Func: func(cfg *testConfig, val string) error {
						cfg.StringVal = val
						return nil
					},
				},
			},
			want: &testConfig{
				StringVal: "a",
				IntVal:    123,
			},
		},
		"ok, required mapping, variable provided": {
			config: &testConfig{
				StringVal: "a",
				IntVal:    123,
			},
			environ: map[string]string{
				"STRING_VAL": "b",
			},
			mapping: map[string]config.EnvMapping[testConfig]{
				"STRING_VAL": {
					Required: true, // Required
					Func: func(cfg *testConfig, val string) error {
						cfg.StringVal = val
						return nil
					},
				},
			},
			want: &testConfig{
				StringVal: "b",
				IntVal:    123,
			},
		},
		"ok, multiple mappings, all provided": {
			config: &testConfig{
				StringVal: "a",
				IntVal:    123,
			},
			environ: map[string]string{
				"STRING_VAL": "b",
				"INT_VAL":    "456",
			},
			mapping: map[string]config.EnvMapping[testConfig]{
				"STRING_VAL": {
					Required: true,
					Func: func(cfg *testConfig, val string) error {
						cfg.StringVal = val
						return nil
					},
				},
				"INT_VAL": {
					Required: true,
					Func: func(cfg *testConfig, val string) error {
						return config.MapEnvInt(&cfg.IntVal, val)
					},
				},
			},
			want: &testConfig{
				StringVal: "b",
				IntVal:    456,
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// can't run these tests in parallel, they share the same environment.
			setupEnviron(t, tc.environ)

			got := tc.config
			err := config.MergeEnv(got, tc.mapping)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	t.Run("fail, required env variables not set", func(t *testing.T) {
		mappings := map[string]config.EnvMapping[testConfig]{
			"STRING_VAL": {
				Required: true,
				Func: func(cfg *testConfig, val string) error {
					cfg.StringVal = val
					return nil
				},
			},
			"INT_VAL": {
				Required: true,
				Func: func(cfg *testConfig, val string) error {
					return config.MapEnvInt(&cfg.IntVal, val)
				},
			},
		}

		got := &testConfig{}
		err := config.MergeEnv(got, mappings)
		require.Error(t, err)
		// ensure missing environment variables are mentioned in the error message.
		require.Contains(t, err.Error(), "STRING_VAL")
		require.Contains(t, err.Error(), "INT_VAL")
	})

	t.Run("fail, multiple errors are collected", func(t *testing.T) {
		var (
			stringErr = errors.New("string error")
			intErr    = errors.New("int error")
		)
		mappings := map[string]config.EnvMapping[testConfig]{
			"STRING_VAL": {
				Required: true,
				Func: func(cfg *testConfig, val string) error {
					return stringErr
				},
			},
			"INT_VAL": {
				Required: true,
				Func: func(cfg *testConfig, val string) error {
					return intErr
				},
			},
		}

		setupEnviron(t, map[string]string{
			"STRING_VAL": "",
			"INT_VAL":    "",
		})

		got := &testConfig{}
		err := config.MergeEnv(got, mappings)
		require.Error(t, err)
		// ensure errors from environment variables are mentioned in the error message.
		require.Contains(t, err.Error(), "STRING_VAL")
		require.Contains(t, err.Error(), "INT_VAL")
		require.ErrorIs(t, err, stringErr)
		require.ErrorIs(t, err, intErr)
	})

}

func setupEnviron(t *testing.T, environ map[string]string) {
	for key, val := range environ {
		t.Setenv(key, val)
		t.Cleanup(func() {
			require.NoError(t, os.Unsetenv(key))
		})
	}
}
