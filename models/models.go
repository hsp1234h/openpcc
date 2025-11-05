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
package models

import (
	_ "embed"
	"errors"

	"gopkg.in/yaml.v3"
)

// TODO: in the future we may want to make these values model-dependent
const (
	// InputTokenCreditMultiplier is the number of credits consumed per input token.
	InputTokenCreditMultiplier = 0.5
	// OutputTokenCreditMultiplier is the number of credit consumed per output token.
	OutputTokenCreditMultiplier = 2
)

// ErrModelNotFound is returned when a model lookup fails
var ErrModelNotFound = errors.New("model not found")

//go:embed models.yaml
var modelsYaml []byte

// Model represents a model that is available in CONFSEC
type Model struct {
	Name          string `yaml:"name"`
	ContextLength int    `yaml:"context_length"`
}

// GetMaxCreditAmountPerRequest returns the maximum per-request credit amount for a
// model based on its context length
func (m *Model) GetMaxCreditAmountPerRequest() int64 {
	return int64(float64(m.ContextLength) * OutputTokenCreditMultiplier)
}

// models is a list of all available models
var models []Model

// GetModel returns a model by name
func GetModel(name string) (Model, error) {
	for _, model := range models {
		if model.Name == name {
			return model, nil
		}
	}
	return Model{}, ErrModelNotFound
}

// IsValid returns true if the model name is valid
func IsValid(name string) bool {
	_, err := GetModel(name)
	return err == nil
}

// GetMaxCreditAmountPerRequest returns the maximum per-request credit amount of all
// models based on their context lengths
func GetMaxCreditAmountPerRequest() int64 {
	var maxModel Model
	for _, model := range models {
		if model.ContextLength > maxModel.ContextLength {
			maxModel = model
		}
	}
	return maxModel.GetMaxCreditAmountPerRequest()
}

// load models on module startup
func init() {
	err := yaml.Unmarshal(modelsYaml, &models)
	if err != nil {
		panic(err)
	}
}
