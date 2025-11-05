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

package main_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/openpcc/openpcc"
	"github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/main"
	"github.com/openpcc/openpcc/models"
	ctest "github.com/openpcc/openpcc/test"
)

const (
	// Some handle ID which we will surely never reach in the course of testing.
	invalidHandle = uintptr(999999)
)

func TestClientCreate(t *testing.T) {
	localDevIdPolicy := inttest.LocalDevIdentityPolicy()
	successCases := map[string]struct {
		identityPolicySource     int
		oidcIssuer               string
		oidcIssuerRegex          string
		oidcSubject              string
		oidcSubjectRegex         string
		concurrentRequestsTarget int
		maxCandidateNodes        int
		defaultNodeTags          []string
		env                      string
	}{
		"ok, all defaults": {
			identityPolicySource:     int(openpcc.IdentityPolicySourceConfigured),
			oidcIssuer:               localDevIdPolicy.OIDCIssuer,
			oidcIssuerRegex:          localDevIdPolicy.OIDCIssuerRegex,
			oidcSubject:              localDevIdPolicy.OIDCSubject,
			oidcSubjectRegex:         localDevIdPolicy.OIDCSubjectRegex,
			concurrentRequestsTarget: 0,
			maxCandidateNodes:        0,
			defaultNodeTags:          nil,
			env:                      "",
		},
		"ok, custom configs": {
			identityPolicySource:     int(openpcc.IdentityPolicySourceUnsafeRemote),
			oidcIssuer:               "",
			oidcIssuerRegex:          "",
			oidcSubject:              "",
			oidcSubjectRegex:         "",
			concurrentRequestsTarget: 10,
			maxCandidateNodes:        10,
			defaultNodeTags:          []string{"tag1", "tag2"},
			env:                      "staging",
		},
	}
	main.WithGetOpts(getOpts, func() {
		for name, tc := range successCases {
			t.Run(name, func(t *testing.T) {
				handle, err := main.ClientCreate(
					"my-api-url",
					"my-api-key",
					int(openpcc.IdentityPolicySourceUnsafeRemote),
					"",
					"",
					"",
					"",
					tc.concurrentRequestsTarget,
					tc.maxCandidateNodes,
					tc.defaultNodeTags,
					tc.env,
				)
				require.NoError(t, err)
				require.Greater(t, handle, uintptr(0))

				err = main.ClientDestroy(handle)
				require.NoError(t, err)
			})
		}
	})
}

func TestClientDestroy(t *testing.T) {
	main.WithGetOpts(getOpts, func() {
		t.Run("ok", func(t *testing.T) {
			handle, err := main.ClientCreate("my-api-url", "my-api-key", 1, "", "", "", "", 0, 0, nil, "")
			require.NoError(t, err)
			require.Greater(t, handle, uintptr(0))

			err = main.ClientDestroy(handle)
			require.NoError(t, err)
		})
		t.Run("err, invalid handle", func(t *testing.T) {
			err := main.ClientDestroy(invalidHandle)
			require.Error(t, err)
			require.ErrorContains(t, err, main.ErrClientNotFound.Error())
		})
	})
}

func TestClientGetDefaultCreditAmountPerRequest(t *testing.T) {
	main.WithGetOpts(getOpts, func() {
		t.Run("ok", func(t *testing.T) {
			model, err := models.GetModel("llama3.2:1b")
			require.NoError(t, err)
			tags := []string{"llm", "model=" + model.Name}
			handle, err := main.ClientCreate("my-api-url", "my-api-key", 1, "", "", "", "", 0, 0, tags, "")
			require.NoError(t, err)
			require.Greater(t, handle, uintptr(0))
			defer main.ClientDestroy(handle)

			creditAmount, err := main.ClientGetDefaultCreditAmountPerRequest(handle)
			require.NoError(t, err)
			require.LessOrEqual(t, model.GetMaxCreditAmountPerRequest(), creditAmount)
		})
		t.Run("err, invalid handle", func(t *testing.T) {
			_, err := main.ClientGetDefaultCreditAmountPerRequest(invalidHandle)
			require.Error(t, err)
			require.ErrorContains(t, err, main.ErrClientNotFound.Error())
		})
	})
}

func TestClientGetMaxCandidateNodes(t *testing.T) {
	main.WithGetOpts(getOpts, func() {
		t.Run("ok", func(t *testing.T) {
			maxCandidateNodes := 10
			handle, err := main.ClientCreate("my-api-url", "my-api-key", 1, "", "", "", "", 0, maxCandidateNodes, nil, "")
			require.NoError(t, err)
			require.Greater(t, handle, uintptr(0))
			defer main.ClientDestroy(handle)

			result, err := main.ClientGetMaxCandidateNodes(handle)
			require.NoError(t, err)
			require.Equal(t, maxCandidateNodes, result)
		})
		t.Run("err, invalid handle", func(t *testing.T) {
			_, err := main.ClientGetMaxCandidateNodes(invalidHandle)
			require.Error(t, err)
			require.ErrorContains(t, err, main.ErrClientNotFound.Error())
		})
	})
}

func TestClientGetDefaultNodeTags(t *testing.T) {
	main.WithGetOpts(getOpts, func() {
		t.Run("ok", func(t *testing.T) {
			tags := []string{"foo=bar", "baz=qux"}
			handle, err := main.ClientCreate("my-api-url", "my-api-key", 1, "", "", "", "", 0, 0, tags, "")
			require.NoError(t, err)
			require.Greater(t, handle, uintptr(0))
			defer main.ClientDestroy(handle)

			result, err := main.ClientGetDefaultNodeTags(handle)
			require.NoError(t, err)
			require.Equal(t, tags, result)
		})
		t.Run("err, invalid handle", func(t *testing.T) {
			_, err := main.ClientGetDefaultNodeTags(invalidHandle)
			require.Error(t, err)
			require.ErrorContains(t, err, main.ErrClientNotFound.Error())
		})
	})
}

func TestClientSetDefaultNodeTags(t *testing.T) {
	main.WithGetOpts(getOpts, func() {
		t.Run("ok", func(t *testing.T) {
			handle, err := main.ClientCreate("my-api-url", "my-api-key", 1, "", "", "", "", 0, 0, nil, "")
			require.NoError(t, err)
			require.Greater(t, handle, uintptr(0))
			defer main.ClientDestroy(handle)

			tags := []string{"foo=bar", "baz=qux"}
			err = main.ClientSetDefaultNodeTags(handle, tags)
			require.NoError(t, err)

			result, err := main.ClientGetDefaultNodeTags(handle)
			require.NoError(t, err)
			require.Equal(t, tags, result)
		})
		t.Run("err, invalid handle", func(t *testing.T) {
			tags := []string{"foo=bar", "baz=qux"}
			err := main.ClientSetDefaultNodeTags(invalidHandle, tags)
			require.Error(t, err)
			require.ErrorContains(t, err, main.ErrClientNotFound.Error())
		})
	})
}

func TestClientGetWalletStatus(t *testing.T) {
	main.WithGetOpts(getOpts, func() {
		t.Run("ok", func(t *testing.T) {
			handle, err := main.ClientCreate("my-api-url", "my-api-key", 1, "", "", "", "", 0, 0, nil, "")
			require.NoError(t, err)
			require.Greater(t, handle, uintptr(0))
			defer main.ClientDestroy(handle)

			walletStatus, err := main.ClientGetWalletStatus(handle)
			require.NoError(t, err)
			require.NotNil(t, walletStatus)
		})
	})
	t.Run("err, invalid handle", func(t *testing.T) {
		_, err := main.ClientGetWalletStatus(invalidHandle)
		require.Error(t, err)
		require.ErrorContains(t, err, main.ErrClientNotFound.Error())
	})
}

func getOpts() []openpcc.Option {
	innerHTTPClient := &http.Client{
		Timeout: 5 * time.Second,
	}
	wallet := &ctest.FakeWallet{}
	nodeFinder := &ctest.FakeNodeFinder{}
	authClient := &ctest.FakeAuthClient{
		RouterURLFunc: func() string {
			return "http://example.com/router"
		},
	}
	return []openpcc.Option{
		openpcc.WithWallet(wallet),
		openpcc.WithVerifiedNodeFinder(nodeFinder),
		openpcc.WithAuthClient(authClient),
		openpcc.WithAnonHTTPClient(innerHTTPClient),
		openpcc.WithRouterPing(false),
	}
}
