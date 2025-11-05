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

package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Validator can optionally be implemented by configuration to do cross-field
// validation and/or app-specific checks.
type Validator interface {
	IsValid() error
}

// Loads the given configuration by:
// 1. Merging in the given YAML file using MergeYAML.
// 2. Merging in the environment using MergeEnv.
// 3. Calling IsValid on cfg if *T implements the Validator interface.
func Load[T any](cfg *T, yamlFilePath string, envMappings map[string]EnvMapping[T]) error {
	if yamlFilePath != "" {
		yamlFile, err := os.Open(yamlFilePath)
		if err != nil {
			return fmt.Errorf("failed to open YAML file: %w", err)
		}
		defer yamlFile.Close()

		err = MergeYAML(cfg, io.Reader(yamlFile))
		if err != nil {
			return err
		}
	}

	err := MergeEnv(cfg, envMappings)
	if err != nil {
		return err
	}

	validator, ok := any(cfg).(Validator)
	if ok {
		err = validator.IsValid()
		if err != nil {
			return fmt.Errorf("invalid configuration: %w", err)
		}
	}

	return nil
}

// MergeYAML merges the provided YAML data into the provided configuration.
//
// Environment variables in the YAML file will be expanded to their values.
//
// For example:
// `key: ${VAR}` will be expanded to `key: foo` if VAR=foo.
// If an environment variable is missing from the environment, MergeYAML will return
// an error.
//
// To prevent this, provide a default value using the following syntax:
// `key: ${VAR:bar}`, will be expanded to `key: bar` if VAR is not set.
func MergeYAML[T any](cfg *T, yamlSrc io.Reader) error {
	rawYAML, err := io.ReadAll(yamlSrc)
	if err != nil {
		return fmt.Errorf("failed to read the YAML source: %w", err)
	}

	missingKeys := []string{}

	expanded := os.Expand(string(rawYAML), func(rawKey string) string {
		// rawKey is an environment variable with a default value.
		if i := strings.Index(rawKey, ":-"); i != -1 {
			name, defaultVal := rawKey[:i], rawKey[i+2:]
			val, isSet := os.LookupEnv(name)
			if isSet {
				return val
			}
			return defaultVal
		}

		// rawKey is a regular environment variable.
		val, isSet := os.LookupEnv(rawKey)
		if !isSet {
			missingKeys = append(missingKeys, rawKey)
			return ""
		}

		return val
	})

	if len(missingKeys) > 0 {
		return fmt.Errorf("YAML source expects the following environment variables to be set: %v", missingKeys)
	}

	err = yaml.Unmarshal([]byte(expanded), cfg)
	if err != nil {
		return fmt.Errorf("failed to unmarshal YAML to config: %w", err)
	}

	return nil
}

// EnvMapping maps an environment variable to the config.
//
// In general the config will be a struct and an EnvMapping will map
// a environment variable to one or more fields. If the value for the
// environment variable is invalid, EnvMapping should return an error.
//
// An EnvMapping with Required set to true will error when an environment
// variable isn't set.
type EnvMapping[T any] struct {
	Required bool
	Func     func(cfg *T, val string) error
}

// MergeEnv merges the environment variables into a configuration using the provided mappings.
//
// MergeEnv does not stop on the first error, it tries to collect as many errors as possible.
func MergeEnv[T any](cfg *T, mappings map[string]EnvMapping[T]) error {
	var errs error

	for key, mapping := range mappings {
		val, isSet := os.LookupEnv(key)
		if !isSet {
			if mapping.Required {
				errs = errors.Join(errs, fmt.Errorf("missing required env variable %s", key))
			}
			continue
		}
		err := mapping.Func(cfg, val)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("error for env variable %s: %w", key, err))
		}
	}

	return errs
}

// MapEnvInt is a helper method to map environment variables to integer fields.
func MapEnvInt(tgt *int, val string) error {
	i, err := strconv.Atoi(val)
	if err != nil {
		return err
	}
	*tgt = i
	return nil
}

// MapEnvInt is a helper method to map environment variables to bool fields.
func MapEnvBool(tgt *bool, val string) error {
	b, err := strconv.ParseBool(val)
	if err != nil {
		return err
	}
	*tgt = b
	return nil
}

// FilenameFromArgs parses the config file flag from the command line arguments.
func FilenameFromArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("service", flag.ContinueOnError)
	configPathFlag := fs.String("config", "config.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		return "", err
	}

	cp, err := filepath.Abs(*configPathFlag)
	if err != nil {
		return "", fmt.Errorf("invalid config path: %w", err)
	}

	return cp, nil
}
