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
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/transparency"
	"github.com/stretchr/testify/require"
)

func TestSigner(t *testing.T) {
	t.Run("ok, create signer configured for production", func(t *testing.T) {
		_, err := transparency.NewSigner(transparency.SignerConfig{
			Environment:               "prod",
			OIDCToken:                 "invalid", // should be ok, we're not signing anything here.
			LocalTrustedRootCachePath: "",
		}, &http.Client{
			Timeout: 30 * time.Second,
		})
		require.NoError(t, err)
	})

	t.Run("fail, sign statement, invalid statement", func(t *testing.T) {
		signer := test.LocalDevSigner(t, "test")

		statement := newGreetingStatement(t, "hello world!")
		statement.Subject = nil // missing subject

		_, err := signer.SignStatement(t.Context(), statement)
		require.Error(t, err)
	})
}

func TestSignerSignReal(t *testing.T) {
	oidcToken := os.Getenv("TEST_TRANSPARENCY_OIDC_TOKEN")
	if oidcToken == "" {
		// skip tests if there is no token. These tests should generally
		// only be ran to regenerate the files in testdata.
		t.Skip()
	}

	t.Run("ok, sign", func(t *testing.T) {
		signer := test.LocalDevSigner(t, oidcToken)

		bundle, err := signer.Sign(t.Context(), []byte("hello world!"))
		require.NoError(t, err)

		fmt.Println(base64.StdEncoding.EncodeToString(bundle))
	})

	t.Run("ok, sign statement", func(t *testing.T) {
		signer := test.LocalDevSigner(t, oidcToken)
		statement := newGreetingStatement(t, "hello mars!")

		bundle, err := signer.SignStatement(t.Context(), statement)
		require.NoError(t, err)

		fmt.Println(base64.StdEncoding.EncodeToString(bundle))
	})

	t.Run("ok, sign statement with multiple subjects", func(t *testing.T) {
		signer := test.LocalDevSigner(t, oidcToken)
		statement := newConversationStatement(t, "hello world!", "goodbye world!")

		bundle, err := signer.SignStatement(t.Context(), statement)
		require.NoError(t, err)

		fmt.Println(base64.StdEncoding.EncodeToString(bundle))
	})
}
