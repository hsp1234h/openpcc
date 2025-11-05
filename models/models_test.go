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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestModelsLoad(t *testing.T) {
	require.NotEmpty(t, models)
	model := models[0]
	require.NotEmpty(t, model.Name)
	require.Greater(t, model.ContextLength, 0)
}

func TestGetModel(t *testing.T) {
	t.Run("get model success", func(t *testing.T) {
		model, err := GetModel("llama3.2:1b")
		require.NoError(t, err)
		require.Equal(t, "llama3.2:1b", model.Name)
		require.Greater(t, model.ContextLength, 0)
	})
	t.Run("get model not found", func(t *testing.T) {
		_, err := GetModel("clyde-gorkus:one-quadrillion")
		require.Error(t, err)
	})
}

func TestGetMaxCreditAmountPerRequest(t *testing.T) {
	maxContextLength := GetMaxCreditAmountPerRequest()
	require.Greater(t, maxContextLength, int64(0))
}
