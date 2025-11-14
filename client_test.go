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
package openpcc_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	mathrand "math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidentsecurity/twoway"
	"github.com/google/uuid"
	"github.com/openpcc/openpcc"
	"github.com/openpcc/openpcc/ahttp"
	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/anonpay/wallet"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/httpfmt"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/messages"
	"github.com/openpcc/openpcc/models"
	routerapi "github.com/openpcc/openpcc/router/api"
	"github.com/openpcc/openpcc/tags"
	ctest "github.com/openpcc/openpcc/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewClient(t *testing.T) {
	clientWithModConfig := func(_ *testing.T, modFunc func(*openpcc.Config)) (*openpcc.Client, error) {
		// in reality we want this to be a client configured with a OHTTP transport, for these tests
		// we're only interested in the app-specific layer so we ignore OHTTP.
		innerHTTPClient := &http.Client{
			Timeout: 5 * time.Second,
		}

		w := &ctest.FakeWallet{}
		nodeFinder := &ctest.FakeNodeFinder{}
		idPolicy := test.LocalDevIdentityPolicy()

		cfg := openpcc.DefaultConfig()
		cfg.APIKey = "test api key"
		cfg.APIURL = "localhost:9999"
		cfg.TransparencyIdentityPolicy = &idPolicy
		modFunc(&cfg)

		authClient := &ctest.FakeAuthClient{
			RouterURLFunc: func() string {
				return "http://example.com/router"
			},
		}

		return openpcc.NewFromConfig(t.Context(), cfg,
			openpcc.WithWallet(w),
			openpcc.WithVerifiedNodeFinder(nodeFinder),
			openpcc.WithAnonHTTPClient(innerHTTPClient),
			openpcc.WithRouterPing(false),
			openpcc.WithAuthClient(authClient),
		)
	}

	maxCreditAmount, err := openpcc.RoundCreditAmount(models.GetMaxCreditAmountPerRequest())
	require.NoError(t, err)

	tests := map[string]struct {
		configFunc func(*openpcc.Config)
		assertFunc func(*testing.T, *openpcc.Client)
	}{
		"ok, default config": {
			configFunc: func(c *openpcc.Config) {},
			assertFunc: func(t *testing.T, c *openpcc.Client) {
				require.Equal(t, maxCreditAmount, c.DefaultRequestParams().CreditAmount)
				require.Equal(t, maxCreditAmount, c.MaxCreditAmountPerRequest())
			},
		},
		"ok, explicit credit amount": {
			configFunc: func(c *openpcc.Config) {
				c.DefaultRequestParams.CreditAmount = 1000
			},
			assertFunc: func(t *testing.T, c *openpcc.Client) {
				require.Equal(t, int64(1024), c.DefaultRequestParams().CreditAmount)
				require.Equal(t, maxCreditAmount, c.MaxCreditAmountPerRequest())
			},
		},
		"ok, explicit max credit amount": {
			configFunc: func(c *openpcc.Config) {
				c.MaxCreditAmountPerRequest = 20000        // Set higher than auto-calculated default
				c.DefaultRequestParams.CreditAmount = 1000 // Set explicit lower amount
			},
			assertFunc: func(t *testing.T, c *openpcc.Client) {
				require.Equal(t, int64(1024), c.DefaultRequestParams().CreditAmount)
				require.Equal(t, int64(20480), c.MaxCreditAmountPerRequest())
			},
		},
		"ok, model-specific credit amount calculation": {
			configFunc: func(c *openpcc.Config) {
				// Set a model in node tags, should calculate credit amount from model's context length
				c.DefaultRequestParams.NodeTags = []string{"llm", "model=llama3.2:1b"}
			},
			assertFunc: func(t *testing.T, c *openpcc.Client) {
				model, err := models.GetModel("llama3.2:1b")
				require.NoError(t, err)
				expectedCreditAmount := model.GetMaxCreditAmountPerRequest()
				require.LessOrEqual(t, expectedCreditAmount, c.DefaultRequestParams().CreditAmount)
				require.Equal(t, maxCreditAmount, c.MaxCreditAmountPerRequest())
			},
		},
		"ok, auto-calculated credit and max amounts": {
			configFunc: func(c *openpcc.Config) {
				// Both should be auto-calculated from max context length
				c.DefaultRequestParams.CreditAmount = 0
				c.MaxCreditAmountPerRequest = 0
			},
			assertFunc: func(t *testing.T, c *openpcc.Client) {
				require.Equal(t, maxCreditAmount, c.DefaultRequestParams().CreditAmount)
				require.Equal(t, maxCreditAmount, c.MaxCreditAmountPerRequest())
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client, err := clientWithModConfig(t, tc.configFunc)
			require.NoError(t, err)

			if tc.assertFunc != nil {
				tc.assertFunc(t, client)
			}
		})
	}
	failTests := map[string]func(*openpcc.Config){
		"fail, missing api key": func(c *openpcc.Config) {
			c.APIKey = ""
		},
		"fail, invalid model in default node tags": func(c *openpcc.Config) {
			c.DefaultRequestParams.NodeTags = []string{"llm", "model=invalid-model"}
			c.DefaultRequestParams.CreditAmount = 0 // Should trigger model lookup
		},
		"fail, multiple models in default node tags": func(c *openpcc.Config) {
			c.DefaultRequestParams.NodeTags = []string{"llm", "model=llama3.2:1b", "model=llama3.2:2b"}
		},
		"fail, no identity policy": func(c *openpcc.Config) {
			c.TransparencyIdentityPolicy = nil
		},
		"fail, identity policy with no issuer or issuer regex": func(c *openpcc.Config) {
			policy := test.LocalDevIdentityPolicy()
			policy.OIDCIssuer = ""
			policy.OIDCIssuerRegex = ""
			c.TransparencyIdentityPolicy = &policy
		},
		"fail, identity policy with no subject or subject regex": func(c *openpcc.Config) {
			policy := test.LocalDevIdentityPolicy()
			policy.OIDCSubject = ""
			policy.OIDCSubjectRegex = ""
			c.TransparencyIdentityPolicy = &policy
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := clientWithModConfig(t, tc)
			require.Error(t, err)
		})
	}
}

func TestSetDefaultCreditAmountPerRequest(t *testing.T) {
	newClient := func(t *testing.T) *openpcc.Client {
		// in reality we want this to be a client configured with a OHTTP transport, for these tests
		// we're only interested in the app-specific layer so we ignore OHTTP.
		anonHTTPClient := &http.Client{
			Timeout: 5 * time.Second,
		}

		w := &ctest.FakeWallet{}
		nodeFinder := &ctest.FakeNodeFinder{}
		idPolicy := test.LocalDevIdentityPolicy()

		cfg := openpcc.DefaultConfig()
		cfg.APIKey = "test api key"
		cfg.APIURL = "localhost:9999"
		cfg.TransparencyIdentityPolicy = &idPolicy
		authClient := &ctest.FakeAuthClient{
			RouterURLFunc: func() string {
				return "http://example.com/router"
			},
		}

		c, err := openpcc.NewFromConfig(t.Context(), cfg,
			openpcc.WithWallet(w),
			openpcc.WithVerifiedNodeFinder(nodeFinder),
			openpcc.WithAnonHTTPClient(anonHTTPClient),
			openpcc.WithRouterPing(false),
			openpcc.WithAuthClient(authClient),
		)

		require.NoError(t, err)

		return c
	}

	t.Run("ok, valid limit", func(t *testing.T) {
		c := newClient(t)

		err := c.SetDefaultCreditAmountPerRequest(34)
		require.NoError(t, err)

		require.Equal(t, int64(34), c.DefaultRequestParams().CreditAmount)
	})

	failTests := map[string]int64{
		"fail, default credit amount over max credit amount": 999999999, // Very high value to exceed any reasonable max
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			c := newClient(t)

			err := c.SetDefaultCreditAmountPerRequest(tc)
			require.Error(t, err)
		})
	}
}

func TestSetDefaultNodeTags(t *testing.T) {
	newClient := func(t *testing.T) *openpcc.Client {
		// in reality we want this to be a client configured with a OHTTP transport, for these tests
		// we're only interested in the app-specific layer so we ignore OHTTP.
		anonHTTPClient := &http.Client{
			Timeout: 5 * time.Second,
		}

		w := &ctest.FakeWallet{}
		nodeFinder := &ctest.FakeNodeFinder{}

		idPolicy := test.LocalDevIdentityPolicy()

		cfg := openpcc.DefaultConfig()
		cfg.APIKey = "test api key"
		cfg.APIURL = "localhost:9999"
		cfg.TransparencyIdentityPolicy = &idPolicy
		authClient := &ctest.FakeAuthClient{
			RouterURLFunc: func() string {
				return "http://example.com/router"
			},
		}

		c, err := openpcc.NewFromConfig(t.Context(), cfg,
			openpcc.WithWallet(w),
			openpcc.WithVerifiedNodeFinder(nodeFinder),
			openpcc.WithAnonHTTPClient(anonHTTPClient),
			openpcc.WithRouterPing(false),
			openpcc.WithAuthClient(authClient),
		)

		require.NoError(t, err)

		return c
	}

	t.Run("ok, valid limit", func(t *testing.T) {
		c := newClient(t)

		model, err := models.GetModel("llama3.2:1b")
		require.NoError(t, err)

		tags := []string{"llm", "model=" + model.Name}

		err = c.SetDefaultNodeTags(tags)
		require.NoError(t, err)

		require.Equal(t, tags, c.DefaultRequestParams().NodeTags)
		expectedCreditAmount, err := openpcc.RoundCreditAmount(models.GetMaxCreditAmountPerRequest())
		require.NoError(t, err)
		require.Equal(t, expectedCreditAmount, c.DefaultRequestParams().CreditAmount)
	})

	failTests := map[string][]string{
		"fail, invalid model in default node tags":   {"llm", "model=clyde-gorkus:one-trillion"},
		"fail, multiple models in default node tags": {"llm", "model=llama3.2:1b", "model=qwen2:1.5b-instruct"},
	}

	for name, tags := range failTests {
		t.Run(name, func(t *testing.T) {
			c := newClient(t)

			err := c.SetDefaultNodeTags(tags)
			require.Error(t, err)
		})
	}
}

func TestClientAsTransport(t *testing.T) {
	const (
		apiKey = "test-key"
	)

	newClientForNodes := func(t *testing.T, endpointURL string, nodes []openpcc.VerifiedNode) (*openpcc.Client, *ctest.FakeWallet, *ctest.FakeNodeFinder, *http.Client) {
		w := &ctest.FakeWallet{}
		w.SetDefaultCreditAmountFunc = func(limit int64) error {
			return nil
		}
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Fail(t, "unexpected begin payment")
			return nil, assert.AnError
		}

		nodeFinder := &ctest.FakeNodeFinder{
			FindVerifiedNodesFunc: func(ctx context.Context, maxNodes int, tags tags.Tags) ([]openpcc.VerifiedNode, error) {
				assert.Equal(t, maxNodes, len(nodes))
				for _, node := range nodes {
					assert.Equal(t, len(node.Manifest.Tags), len(tags))
				}
				if len(nodes) > maxNodes {
					return nodes[:maxNodes], nil
				}
				return nodes, nil
			},
		}

		// in reality we want this to be a client configured with a OHTTP transport, for these tests
		// we're only interested in the app-specific layer so we ignore OHTTP.
		innerHTTPClient := &http.Client{
			Timeout: 5 * time.Second,
		}

		idPolicy := test.LocalDevIdentityPolicy()

		cfg := openpcc.DefaultConfig()
		cfg.APIKey = apiKey
		cfg.APIURL = "localhost:9999"
		cfg.TransparencyIdentityPolicy = &idPolicy

		tcloudClient, err := openpcc.NewFromConfig(
			t.Context(),
			cfg,
			openpcc.WithWallet(w),
			openpcc.WithVerifiedNodeFinder(nodeFinder),
			openpcc.WithAnonHTTPClient(innerHTTPClient),
			openpcc.WithRouterURL(endpointURL),
			openpcc.WithRouterPing(false),
			openpcc.WithMaxCandidateNodes(len(nodes)),
		)
		require.NoError(t, err)

		err = tcloudClient.SetDefaultModel("llama3.2:1b")
		require.NoError(t, err)

		return tcloudClient, w, nodeFinder, innerHTTPClient
	}

	newRefund := func(t *testing.T, val int) (*anonpay.UnblindedCredit, string) {
		value, err := currency.Rounded(float64(val), 1)
		require.NoError(t, err)
		refund := anonpaytest.MustUnblindCredit(t.Context(), value)
		refundProto, err := refund.MarshalProto()
		require.NoError(t, err)
		refundBytes, err := proto.Marshal(refundProto)
		require.NoError(t, err)
		refundB64 := base64.StdEncoding.EncodeToString(refundBytes)
		return refund, refundB64
	}

	closeAndVerify := func(t *testing.T, tcloudClient *openpcc.Client, w *ctest.FakeWallet, f *ctest.FakeNodeFinder) {
		require.Equal(t, w.CloseCalls, 0)
		require.Equal(t, f.CloseCalls, 0)
		// close the client and verify the wallet and node finders are closed.
		err := tcloudClient.Close(t.Context())
		require.NoError(t, err)
		require.Equal(t, w.CloseCalls, 1)
		require.Equal(t, f.CloseCalls, 1)
	}

	t.Run("ok, default request parameters", func(t *testing.T) {
		const (
			requestData     = "private data"
			validStatusCode = http.StatusCreated
			validResponse   = "hello world from a compute node"
		)

		handler, nodes := validHandler(t, 1, func(r *http.Request) *http.Response {
			test.AssertReadAll(t, []byte(requestData), r.Body)
			return &http.Response{
				StatusCode: validStatusCode,
				Body:       io.NopCloser(strings.NewReader(validResponse)),
			}
		})

		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		wantedAmount := tcloudClient.DefaultRequestParams().CreditAmount
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody(requestData)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.True(t, reqBdy.closed)

		require.Equal(t, validStatusCode, resp.StatusCode)
		test.RequireReadAll(t, []byte(validResponse), resp.Body)

		payment.TestVerifySuccess(t, nil)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("ok, updated default request parameters", func(t *testing.T) {
		const (
			requestData     = "private data"
			validStatusCode = http.StatusCreated
			validResponse   = "hello world from a compute node"
		)

		handler, nodes := validHandler(t, 1, func(r *http.Request) *http.Response {
			test.AssertReadAll(t, []byte(requestData), r.Body)
			return &http.Response{
				StatusCode: validStatusCode,
				Body:       io.NopCloser(strings.NewReader(validResponse)),
			}
		})

		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		// TODO: set wantedAmount to int64(34) (rather than models.GetMaxCreditAmountPerRequest())
		// once the wallet implements SetDefaultCreditAmount
		// wantedAmount := int64(34)
		wantedAmount, err := openpcc.RoundCreditAmount(models.GetMaxCreditAmountPerRequest())
		require.NoError(t, err)

		payment := ctest.NewFakePayment(t, wantedAmount)
		w.SetDefaultCreditAmountFunc = func(limit int64) error {
			assert.Equal(t, limit, wantedAmount)
			return nil
		}
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		// setup node finder expectations
		nodeFinder.FindVerifiedNodesFunc = func(ctx context.Context, maxNodes int, tagslist tags.Tags) ([]openpcc.VerifiedNode, error) {
			assert.Equal(t, maxNodes, 1)
			wantTags := test.Must(tags.FromSlice([]string{"llm", "beta", "test", "model=llama3.2:1b"}))
			assert.Equal(t, wantTags, tagslist)
			if len(nodes) > maxNodes {
				return nodes[:maxNodes], nil
			}
			return nodes, nil
		}

		// TODO: uncomment once the wallet implements SetDefaultCreditAmount
		// update default request parameters
		// err := tcloudClient.SetDefaultCreditAmountPerRequest(34)
		// require.NoError(t, err)

		// update wanted amount since changing the model updates the default credit amount
		newModelName := "llama3.2:1b"
		// TODO: uncomment once the wallet implements SetDefaultCreditAmount and SetDefaultModel
		// updates the default credit amout per request
		// newModel, err := models.GetModel(newModelName)
		// require.NoError(t, err)
		// wantedAmount = newModel.GetMaxCreditAmountPerRequest()

		tcloudClient.SetDefaultNodeTags([]string{"llm", "beta", "test"})
		tcloudClient.SetDefaultModel(newModelName)

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody(requestData)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.True(t, reqBdy.closed)

		require.Equal(t, validStatusCode, resp.StatusCode)
		test.RequireReadAll(t, []byte(validResponse), resp.Body)

		payment.TestVerifySuccess(t, nil)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("ok, request parameters from headers", func(t *testing.T) {
		const (
			requestData     = "private data"
			validStatusCode = http.StatusCreated
			validResponse   = "hello world from a compute node"
		)

		handler, nodes := validHandler(t, 1, func(r *http.Request) *http.Response {
			test.AssertReadAll(t, []byte(requestData), r.Body)
			return &http.Response{
				StatusCode: validStatusCode,
				Body:       io.NopCloser(strings.NewReader(validResponse)),
			}
		})

		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		wantedAmount := int64(34)
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		// setup node finder expectations
		nodeFinder.FindVerifiedNodesFunc = func(ctx context.Context, maxNodes int, tagslist tags.Tags) ([]openpcc.VerifiedNode, error) {
			assert.Equal(t, maxNodes, 1)
			wantTags := test.Must(tags.FromSlice([]string{"llm", "beta", "test", "model=qwen2:1.5b-instruct"}))
			assert.Equal(t, wantTags, tagslist)
			if len(nodes) > maxNodes {
				return nodes[:maxNodes], nil
			}
			return nodes, nil
		}

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody(requestData)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)
		req.Header.Set(openpcc.CreditAmountHeader, "34")
		req.Header.Set(openpcc.NodeTagsHeader, "llm,beta,test,model=qwen2:1.5b-instruct")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.True(t, reqBdy.closed)

		require.Equal(t, validStatusCode, resp.StatusCode)
		test.RequireReadAll(t, []byte(validResponse), resp.Body)

		payment.TestVerifySuccess(t, nil)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("ok, request with credit amount header at maximum", func(t *testing.T) {
		const (
			requestData     = "private data"
			validStatusCode = http.StatusCreated
			validResponse   = "hello world from a compute node"
		)

		handler, nodes := validHandler(t, 1, func(r *http.Request) *http.Response {
			test.AssertReadAll(t, []byte(requestData), r.Body)
			return &http.Response{
				StatusCode: validStatusCode,
				Body:       io.NopCloser(strings.NewReader(validResponse)),
			}
		})

		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		wantedAmount := tcloudClient.MaxCreditAmountPerRequest()
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody(requestData)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)
		req.Header.Set(openpcc.CreditAmountHeader, strconv.FormatInt(wantedAmount, 10))

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.True(t, reqBdy.closed)

		require.Equal(t, validStatusCode, resp.StatusCode)
		test.RequireReadAll(t, []byte(validResponse), resp.Body)

		payment.TestVerifySuccess(t, nil)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("ok, response with refund, refund processed due to body being read", func(t *testing.T) {
		const (
			requestData     = "private data"
			validStatusCode = http.StatusCreated
			validResponse   = "hello world from a compute node"
		)

		refund, refundHeaderVal := newRefund(t, 1)

		inner, nodes := validHandler(t, 1, func(r *http.Request) *http.Response {
			test.AssertReadAll(t, []byte(requestData), r.Body)
			return &http.Response{
				StatusCode: validStatusCode,
				Body:       io.NopCloser(strings.NewReader(validResponse)),
			}
		})

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Trailer", ahttp.RefundHeader)
			inner.ServeHTTP(w, r)
			w.Header().Set(ahttp.RefundHeader, refundHeaderVal)
		})

		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		wantedAmount := tcloudClient.DefaultRequestParams().CreditAmount
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody(requestData)

		gotRefundAmount := int64(0)
		ctx := openpcc.ContextWithRefundCallback(t.Context(), func(amount int64) {
			gotRefundAmount += amount
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		// we'll close the response body later.
		require.True(t, reqBdy.closed)

		require.Equal(t, validStatusCode, resp.StatusCode)

		// read the body which should process the response.
		test.RequireReadAll(t, []byte(validResponse), resp.Body)

		payment.TestVerifySuccess(t, refund)

		// verify the refund from the callback
		require.Equal(t, gotRefundAmount, payment.TestUnspendCredit().Value().AmountOrZero())

		// close the response body to process the refund.
		err = resp.Body.Close()
		require.NoError(t, err)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("ok, response with refund, refund is handled even if body is not read", func(t *testing.T) {
		const (
			requestData     = "private data"
			validStatusCode = http.StatusCreated
			validResponse   = "hello world from a compute node"
		)

		refund, refundHeaderVal := newRefund(t, 1)

		inner, nodes := validHandler(t, 1, func(r *http.Request) *http.Response {
			test.AssertReadAll(t, []byte(requestData), r.Body)
			return &http.Response{
				StatusCode: validStatusCode,
				Body:       io.NopCloser(strings.NewReader(validResponse)),
			}
		})

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Trailer", ahttp.RefundHeader)
			inner.ServeHTTP(w, r)
			w.Header().Set(ahttp.RefundHeader, refundHeaderVal)
		})

		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		wantedAmount := tcloudClient.DefaultRequestParams().CreditAmount
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody(requestData)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		// we'll close the response body later.
		require.True(t, reqBdy.closed)

		require.Equal(t, validStatusCode, resp.StatusCode)

		// note: we don't read the body.

		// close the response body to process the refund.
		err = resp.Body.Close()
		require.NoError(t, err)

		payment.TestVerifySuccess(t, refund)

		// verify that closing the body again does not do a double refund.
		err = resp.Body.Close()
		require.NoError(t, err)

		payment.TestVerifySuccess(t, refund)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("ok, multiple nodes", func(t *testing.T) {
		const (
			requestData     = "private data"
			validStatusCode = http.StatusCreated
			validResponse   = "hello world from a compute node"
		)

		handler, nodes := validHandler(t, 1, func(r *http.Request) *http.Response {
			test.AssertReadAll(t, []byte(requestData), r.Body)
			return &http.Response{
				StatusCode: validStatusCode,
				Body:       io.NopCloser(strings.NewReader(validResponse)),
			}
		})

		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, _, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		wantedAmount := tcloudClient.DefaultRequestParams().CreditAmount
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody(requestData)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.True(t, reqBdy.closed)

		require.Equal(t, validStatusCode, resp.StatusCode)
		test.RequireReadAll(t, []byte(validResponse), resp.Body)

		payment.TestVerifySuccess(t, nil)
	})

	t.Run("ok, host provided via host header", func(t *testing.T) {
		const (
			requestData     = "private data"
			validStatusCode = http.StatusCreated
			validResponse   = "hello world from a compute node"
		)

		handler, nodes := validHandler(t, 1, func(r *http.Request) *http.Response {
			test.AssertReadAll(t, []byte(requestData), r.Body)
			return &http.Response{
				StatusCode: validStatusCode,
				Body:       io.NopCloser(strings.NewReader(validResponse)),
			}
		})

		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		wantedAmount := tcloudClient.DefaultRequestParams().CreditAmount
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody(requestData)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://example.com/test", reqBdy)
		require.NoError(t, err)
		req.Host = "confsec.invalid"

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.True(t, reqBdy.closed)

		require.Equal(t, validStatusCode, resp.StatusCode)
		test.RequireReadAll(t, []byte(validResponse), resp.Body)

		payment.TestVerifySuccess(t, nil)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("ok, hostname with port", func(t *testing.T) {
		const (
			requestData     = "private data"
			validStatusCode = http.StatusCreated
			validResponse   = "hello world from a compute node"
		)

		handler, nodes := validHandler(t, 1, func(r *http.Request) *http.Response {
			test.AssertReadAll(t, []byte(requestData), r.Body)
			return &http.Response{
				StatusCode: validStatusCode,
				Body:       io.NopCloser(strings.NewReader(validResponse)),
			}
		})

		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		wantedAmount := tcloudClient.DefaultRequestParams().CreditAmount
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody(requestData)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://confsec.invalid:80/test", reqBdy)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.True(t, reqBdy.closed)

		require.Equal(t, validStatusCode, resp.StatusCode)
		test.RequireReadAll(t, []byte(validResponse), resp.Body)

		payment.TestVerifySuccess(t, nil)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("fail, network failure", func(t *testing.T) {
		nodes, _ := newVerifiedNodes(t, 1)
		tcloudClient, w, nodeFinder, innerClient := newClientForNodes(t, "http://127.0.0.1", nodes)

		// to simulate a network failure we return an error from the inner client's tranport.
		innerClient.Transport = &errTransport{
			err: assert.AnError,
		}

		// setup wallet expectations
		wantedAmount := tcloudClient.DefaultRequestParams().CreditAmount
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody("private data")
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)

		_, err = httpClient.Do(req)
		require.ErrorIs(t, err, assert.AnError)
		require.True(t, reqBdy.closed) // request body should be closed even when there are errors.

		payment.TestVerifyCancel(t)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("fail, invalid hostname", func(t *testing.T) {
		const (
			requestData     = "private data"
			validStatusCode = http.StatusCreated
			validResponse   = "hello world from a compute node"
		)

		handler, nodes := validHandler(t, 1, func(r *http.Request) *http.Response {
			assert.Fail(t, "unexpected call to handler")
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       http.NoBody,
			}
		})

		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		wantedAmount := tcloudClient.DefaultRequestParams().CreditAmount
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody(requestData)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1", reqBdy)
		require.NoError(t, err)

		_, err = httpClient.Do(req)
		require.Error(t, err)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("fail, invalid hostname as host", func(t *testing.T) {
		const (
			requestData     = "private data"
			validStatusCode = http.StatusCreated
			validResponse   = "hello world from a compute node"
		)

		handler, nodes := validHandler(t, 1, func(r *http.Request) *http.Response {
			assert.Fail(t, "unexpected call to handler")
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       http.NoBody,
			}
		})

		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		wantedAmount := tcloudClient.DefaultRequestParams().CreditAmount
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody(requestData)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)
		req.Host = "example.com"

		_, err = httpClient.Do(req)
		require.Error(t, err)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("fail, request with credit amount header over maximum", func(t *testing.T) {
		handler, nodes := validHandler(t, 1, func(r *http.Request) *http.Response {
			assert.Fail(t, "unexpected call to handler")
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       http.NoBody,
			}
		})

		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody("private data")
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)
		req.Header.Set(openpcc.CreditAmountHeader, strconv.FormatInt(tcloudClient.MaxCreditAmountPerRequest()+1, 10))

		_, err = httpClient.Do(req)
		require.Error(t, err)
		require.ErrorIs(t, err, openpcc.ErrMaxCreditAmountViolated)
		require.True(t, reqBdy.closed) // request body should be closed even when there are errors.

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("fail, no nodes found", func(t *testing.T) {
		handler, nodes := validHandler(t, 1, func(r *http.Request) *http.Response {
			assert.Fail(t, "unexpected call to handler")
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       http.NoBody,
			}
		})

		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		wantedAmount := tcloudClient.DefaultRequestParams().CreditAmount
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		// setup node finder expectations
		nodeFinder.FindVerifiedNodesFunc = func(ctx context.Context, maxNodes int, tags tags.Tags) ([]openpcc.VerifiedNode, error) {
			return []openpcc.VerifiedNode{}, nil // no error but zero nodes.
		}

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody("private data")
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)

		_, err = httpClient.Do(req)
		require.Error(t, err)
		require.ErrorIs(t, err, openpcc.ErrNotEnoughVerifiedNodes)
		require.True(t, reqBdy.closed) // request body should be closed even when there are errors.

		payment.TestVerifyCancel(t)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("fail, cancelling context cancels router request as well", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())

		handler, nodes := validHandler(t, 1, func(r *http.Request) *http.Response {
			// cancel the context when a request reaches the handler
			cancel()
			// give client some time to handle the cancel before we write the response.
			time.Sleep(500 * time.Millisecond)

			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       http.NoBody,
			}
		})

		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		wantedAmount := tcloudClient.DefaultRequestParams().CreditAmount
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody("private data")
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)

		_, err = httpClient.Do(req)
		require.Error(t, err)
		require.ErrorIs(t, err, context.Canceled)
		require.True(t, reqBdy.closed) // request body should be closed even when there are errors.

		payment.TestVerifyCancel(t)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("fail, router returns error response", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httpfmt.BinaryServerError(w, r)
		})

		nodes, _ := newVerifiedNodes(t, 1)
		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		// setup wallet expectations
		wantedAmount := tcloudClient.DefaultRequestParams().CreditAmount
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		httpClient := &http.Client{
			Timeout:   5 * time.Second,
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody("private data")
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)

		_, err = httpClient.Do(req)
		require.Error(t, err)
		require.True(t, reqBdy.closed) // request body should be closed even when there are errors.

		// verify we got a router error
		var gotErr openpcc.RouterError
		require.ErrorAs(t, err, &gotErr)
		wantErr := openpcc.RouterError{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		require.Equal(t, wantErr, gotErr)

		payment.TestVerifyCancel(t)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("fail, request context times out before credit returned", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Fail(t, "unexpected call to handler")
		})

		nodes, _ := newVerifiedNodes(t, 1)
		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		wait := time.Second * 1
		// setup wallet expectations
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
				require.Fail(t, "unexpectedly reached end of timeout")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return nil, errors.New("no credit")
		}

		httpClient := &http.Client{
			Timeout:   wait / 5, // times out before wallet can get credit.
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody("private data")
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)

		_, err = httpClient.Do(req)
		require.Error(t, err)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.True(t, reqBdy.closed) // request body should be closed even when there are errors.

		// since we didn't get any nodes, we don't expect any releases here.

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})

	t.Run("fail, request context times out before nodes returned", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Fail(t, "unexpected call to handler")
		})

		nodes, _ := newVerifiedNodes(t, 1)
		endpointURL := test.RunHandlerWhile(t, handler)
		tcloudClient, w, nodeFinder, _ := newClientForNodes(t, endpointURL, nodes)

		wait := time.Second * 1
		// setup node finder expectations
		nodeFinder.FindVerifiedNodesFunc = func(ctx context.Context, maxNodes int, tags tags.Tags) ([]openpcc.VerifiedNode, error) {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
				require.Fail(t, "unexpectedly reached end of timeout")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return nil, errors.New("no nodes")
		}

		// setup wallet expectations
		wantedAmount := tcloudClient.DefaultRequestParams().CreditAmount
		payment := ctest.NewFakePayment(t, wantedAmount)
		w.BeginPaymentFunc = func(ctx context.Context, amount int64) (wallet.Payment, error) {
			assert.Equal(t, wantedAmount, amount)
			return payment, nil
		}

		httpClient := &http.Client{
			Timeout:   wait / 5, // times out before node finder can find nodes.
			Transport: tcloudClient,
		}

		reqBdy := newRequestBody("private data")
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://confsec.invalid/test", reqBdy)
		require.NoError(t, err)

		_, err = httpClient.Do(req)
		require.Error(t, err)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.True(t, reqBdy.closed) // request body should be closed even when there are errors.

		payment.TestVerifyCancel(t)

		closeAndVerify(t, tcloudClient, w, nodeFinder)
	})
}

// requestBody allows us to check if the request body was closed, something
// roundtripper should always do according to the http.RoundTripper interface.
type requestBody struct {
	io.Reader
	closed bool
}

//nolint:unparam
func newRequestBody(data string) *requestBody {
	return &requestBody{
		Reader: bytes.NewReader([]byte(data)),
		closed: false,
	}
}

func (rb *requestBody) Close() error {
	rb.closed = true
	return nil
}

type responseFunc func(r *http.Request) *http.Response

// validHandler pretends to run the given handler on the returned nodes.
//
//nolint:unparam
func validHandler(t *testing.T, n int, responseFunc responseFunc) (http.Handler, []openpcc.VerifiedNode) {
	candidateHandle := func(w http.ResponseWriter, r *http.Request, candidate routerapi.ComputeCandidate, receiver *twoway.MultiRequestReceiver) {
		req, opener, err := messages.DecapsulateRequest(r.Context(), receiver, candidate.EncapsulatedKey, r.Header.Get("Content-Type"), r.Body)
		require.NoError(t, err)

		sealer, mediaType, err := messages.EncapsulateResponse(opener, responseFunc(req))
		assert.NoError(t, err)

		// set the picked node id on the response so the client can decrypt it.
		w.Header().Set(routerapi.NodeIDHeader, candidate.ID.String())
		w.Header().Set("Content-Type", mediaType)
		if mediaType == messages.MediaTypeResponseChunked {
			w.Header().Set("Transfer-Encoding", "chunked")
		}
		w.WriteHeader(http.StatusOK)
		_, err = io.Copy(w, sealer)
		assert.NoError(t, err)
	}

	nodes, receivers := newVerifiedNodes(t, n)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// simulate router and compute node in this handler.
		var info routerapi.ComputeRequestInfo
		err := info.UnmarshalText([]byte(r.Header.Get(routerapi.RoutingInfoHeader)))
		if err != nil {
			httpfmt.BinaryBadRequest(w, r, "invalid routing info")
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			httpfmt.BinaryServerError(w, r)
			return
		}

		// check if all candidates can handle the request by recording a response for all of them.
		for _, candidate := range info.Candidates {
			receiver, ok := receivers[candidate.ID]
			if !ok {
				httpfmt.BinaryError(w, r, "unknown candidate", http.StatusNotFound)
				return
			}

			rr := httptest.NewRecorder()
			r.Body = io.NopCloser(bytes.NewReader(body)) // candidateHandle consumes the body
			candidateHandle(rr, r, candidate, receiver)
			if rr.Result().StatusCode != http.StatusOK {
				httpfmt.BinaryBadRequest(w, r, "candidate can't handle request")
				return
			}
		}

		// pick a random candidate to write the actual response request.
		i := mathrand.IntN(len(info.Candidates))
		candidate := info.Candidates[i]
		receiver, ok := receivers[candidate.ID]
		if !ok {
			httpfmt.BinaryError(w, r, "unknown target node", http.StatusNotFound)
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(body)) // candidateHandle consumes the body
		candidateHandle(w, r, candidate, receiver)
	})

	return h, nodes
}

func newVerifiedNodes(t *testing.T, n int) ([]openpcc.VerifiedNode, map[uuid.UUID]*twoway.MultiRequestReceiver) {
	nodes := make([]openpcc.VerifiedNode, 0, n)
	receivers := make(map[uuid.UUID]*twoway.MultiRequestReceiver)

	for i := 0; i < n; i++ {
		id := test.DeterministicV7UUID(i)

		receiver, computeData := test.NewComputeNodeReceiver(t)
		receivers[id] = receiver
		nodes = append(nodes, openpcc.VerifiedNode{
			Manifest: routerapi.ComputeManifest{
				ID:       id,
				Tags:     test.Must(tags.FromSlice([]string{"llm", "model=llama3.2:1b"})),
				Evidence: evidence.SignedEvidenceList{}, // not relevant here.
			},
			TrustedData: computeData,
			VerifiedAt:  time.Now(),
		})
	}

	return nodes, receivers
}

type errTransport struct {
	err error
}

func (t *errTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, t.err
}
