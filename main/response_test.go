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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net/http"
	"net/http/httputil"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/confidentsecurity/twoway"
	"github.com/openpcc/openpcc"
	"github.com/openpcc/openpcc/anonpay/wallet"
	"github.com/openpcc/openpcc/httpfmt"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/main"
	"github.com/openpcc/openpcc/messages"
	routerapi "github.com/openpcc/openpcc/router/api"
	"github.com/openpcc/openpcc/tags"
	ctest "github.com/openpcc/openpcc/test"
)

const (
	url = "https://confsec.invalid/test"
)

func TestResponse(t *testing.T) {
	t.Run("response metadata", func(t *testing.T) {
		expectedBody := "hello world"
		rh, cleanup := doRequest(t, http.MethodGet, "foo", func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Proto:      "HTTP/1.1",
				Header: http.Header{
					"Content-Type":  []string{"text/plain"},
					"Custom-Header": []string{"custom-value"},
					"Multi-Header":  []string{"value1", "value2"},
				},
				Body: io.NopCloser(bytes.NewReader([]byte(expectedBody))),
			}
		})
		defer cleanup()

		metadataJSON, err := main.ResponseGetMetadata(rh)
		require.NoError(t, err)

		var metadata main.ResponseMetadata
		err = json.Unmarshal(metadataJSON, &metadata)
		require.NoError(t, err)

		// Verify status code is preserved
		require.Equal(t, http.StatusOK, metadata.StatusCode)

		// Verify headers are preserved
		headerMap := make(map[string][]string)
		for _, kv := range metadata.Headers {
			headerMap[kv.Key] = append(headerMap[kv.Key], kv.Value)
		}
		require.Equal(t, []string{"text/plain"}, headerMap["Content-Type"])
		require.Equal(t, []string{"custom-value"}, headerMap["Custom-Header"])
		require.ElementsMatch(t, []string{"value1", "value2"}, headerMap["Multi-Header"])
	})

	t.Run("response body reading", func(t *testing.T) {
		testCases := []struct {
			name string
			body string
		}{
			{"small text", "hello world"},
			{"empty body", ""},
			{"json data", `{"key": "value", "number": 42}`},
			{"unicode text", "Hello 世界 🌍"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				rh, cleanup := doRequest(t, http.MethodGet, "bar", func(req *http.Request) *http.Response {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader([]byte(tc.body))),
						Header: http.Header{
							"Content-Type":   []string{"text/plain"},
							"Content-Length": []string{strconv.Itoa(len(tc.body))},
						},
						ContentLength: int64(len(tc.body)),
					}
				})
				defer cleanup()

				body, err := main.ResponseGetBody(rh)
				require.NoError(t, err)
				require.Equal(t, tc.body, string(body))
			})
		}
	})

	t.Run("streaming response with ndjson", func(t *testing.T) {
		ndjsonData := `{"line": 1}
{"line": 2}
{"line": 3}`

		rh, cleanup := doRequest(t, http.MethodPost, "baz", func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode:       http.StatusOK,
				TransferEncoding: []string{"chunked"},
				Header: http.Header{
					"Content-Type":      []string{"application/x-ndjson"},
					"Transfer-Encoding": []string{"chunked"},
				},
				Body: io.NopCloser(bytes.NewReader([]byte(ndjsonData))),
			}
		})
		defer cleanup()

		// Verify this is detected as streaming
		streamHandle, err := main.ResponseGetStream(rh)
		require.NoError(t, err)
		defer main.ResponseStreamDestroy(streamHandle)

		// Read line by line
		chunk, err := main.ResponseStreamGetNext(streamHandle)
		require.NoError(t, err, "failed to read chunk")
		require.Equal(t, ndjsonData, string(chunk))

		// Should return nil when done
		chunk, err = main.ResponseStreamGetNext(streamHandle)
		require.NoError(t, err)
		require.Nil(t, chunk)
	})

	t.Run("streaming response binary data", func(t *testing.T) {
		// Create data larger than the default chunk size (128 bytes)
		// Avoid null bytes since C strings are null-terminated
		largeData := make([]byte, 300)
		for i := range largeData {
			largeData[i] = byte((i % 255) + 1)
		}

		rh, cleanup := doRequest(t, http.MethodPost, "", func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode:       http.StatusOK,
				TransferEncoding: []string{"chunked"},
				Header: http.Header{
					"Content-Type":      []string{"application/octet-stream"},
					"Transfer-Encoding": []string{"chunked"},
				},
				Body: io.NopCloser(bytes.NewReader(largeData)),
			}
		})
		defer cleanup()

		streamHandle, err := main.ResponseGetStream(rh)
		require.NoError(t, err)
		defer main.ResponseStreamDestroy(streamHandle)

		var receivedData []byte
		for {
			chunk, err := main.ResponseStreamGetNext(streamHandle)
			require.NoError(t, err)

			if chunk == nil {
				break
			}

			// Each chunk should be <= 128 bytes and > 0 bytes
			require.LessOrEqual(t, len(chunk), 128)
			require.Greater(t, len(chunk), 0)
			receivedData = append(receivedData, chunk...)
		}

		require.Equal(t, largeData, receivedData)
	})

	t.Run("error cases", func(t *testing.T) {
		t.Run("invalid client handle", func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, url, nil)
			require.NoError(t, err)

			reqBytes, err := httputil.DumpRequest(req, true)
			require.NoError(t, err)

			_, err = main.ClientDoRequest(uintptr(999999), reqBytes)
			require.Error(t, err)
			require.ErrorContains(t, err, main.ErrClientNotFound.Error())
		})

		t.Run("malformed HTTP request", func(t *testing.T) {
			nodes, receivers := newVerifiedNodes(t, 1)
			handler := validHandler(t, receivers, func(req *http.Request) *http.Response {
				return &http.Response{StatusCode: http.StatusOK}
			})
			endpointURL := test.RunHandlerWhile(t, handler)
			ch := newClientForNodes(t, nodes, endpointURL)
			defer destroyClient(t, ch)

			malformedRequests := [][]byte{
				[]byte("INVALID REQUEST FORMAT"),
				{},
			}

			for i, malformed := range malformedRequests {
				t.Run(fmt.Sprintf("malformed_%d", i), func(t *testing.T) {
					_, err := main.ClientDoRequest(ch, malformed)
					require.Error(t, err)
				})
			}
		})

		t.Run("invalid response handles", func(t *testing.T) {
			invalidHandle := uintptr(999999)

			t.Run("ResponseGetMetadata", func(t *testing.T) {
				_, err := main.ResponseGetMetadata(invalidHandle)
				require.Error(t, err)
				require.ErrorContains(t, err, main.ErrResponseNotFound.Error())
			})

			t.Run("ResponseGetBody", func(t *testing.T) {
				_, err := main.ResponseGetBody(invalidHandle)
				require.Error(t, err)
				require.ErrorContains(t, err, main.ErrResponseNotFound.Error())
			})

			t.Run("ResponseGetStream", func(t *testing.T) {
				_, err := main.ResponseGetStream(invalidHandle)
				require.Error(t, err)
				require.ErrorContains(t, err, main.ErrResponseNotFound.Error())
			})

			t.Run("ResponseDestroy", func(t *testing.T) {
				err := main.ResponseDestroy(invalidHandle)
				require.Error(t, err)
				require.ErrorContains(t, err, main.ErrResponseNotFound.Error())
			})

			t.Run("ResponseIsStreaming", func(t *testing.T) {
				_, err := main.ResponseIsStreaming(invalidHandle)
				require.Error(t, err)
				require.ErrorContains(t, err, main.ErrResponseNotFound.Error())
			})
		})

		t.Run("body/stream access conflicts", func(t *testing.T) {
			t.Run("ResponseGetBody on streaming response", func(t *testing.T) {
				// Create a streaming response
				rh, cleanup := doRequest(t, http.MethodPost, "", func(req *http.Request) *http.Response {
					return &http.Response{
						StatusCode:       http.StatusOK,
						TransferEncoding: []string{"chunked"},
						Header: http.Header{
							"Content-Type":      []string{"application/x-ndjson"},
							"Transfer-Encoding": []string{"chunked"},
						},
						Body: io.NopCloser(bytes.NewReader([]byte(`{"test": "data"}`))),
					}
				})
				defer cleanup()

				_, err := main.ResponseGetBody(rh)
				require.Error(t, err)
				require.ErrorContains(t, err, main.ErrResponseIsStreaming.Error())
			})

			t.Run("ResponseGetStream on non-streaming response", func(t *testing.T) {
				// Create a non-streaming response
				rh, cleanup := doRequest(t, http.MethodGet, "", func(req *http.Request) *http.Response {
					return &http.Response{
						StatusCode: http.StatusOK,
						Header: http.Header{
							"Content-Type":   []string{"text/plain"},
							"Content-Length": []string{"11"},
						},
						ContentLength: 11,
						Body:          io.NopCloser(bytes.NewReader([]byte("hello world"))),
					}
				})
				defer cleanup()

				_, err := main.ResponseGetStream(rh)
				require.Error(t, err)
				require.ErrorContains(t, err, main.ErrResponseIsNotStreaming.Error())
			})
		})

		t.Run("invalid stream handles", func(t *testing.T) {
			invalidHandle := uintptr(999999)

			t.Run("ResponseStreamGetNext", func(t *testing.T) {
				_, err := main.ResponseStreamGetNext(invalidHandle)
				require.Error(t, err)
				require.ErrorContains(t, err, main.ErrResponseStreamNotFound.Error())
			})

			t.Run("ResponseStreamDestroy", func(t *testing.T) {
				err := main.ResponseStreamDestroy(invalidHandle)
				require.Error(t, err)
				require.ErrorContains(t, err, main.ErrResponseStreamNotFound.Error())
			})
		})
	})

	t.Run("streaming detection", func(t *testing.T) {
		testCases := []struct {
			name          string
			headers       http.Header
			contentLength int64
			status        int
			expected      bool
		}{
			{
				name: "chunked transfer encoding",
				headers: http.Header{
					"Transfer-Encoding": []string{"chunked"},
					"Content-Type":      []string{"text/plain"},
				},
				status:   http.StatusOK,
				expected: true,
			},
			{
				name: "chunked transfer encoding case insensitive",
				headers: http.Header{
					"Transfer-Encoding": []string{"CHUNKED"},
					"Content-Type":      []string{"text/plain"},
				},
				status:   http.StatusOK,
				expected: true,
			},
			{
				name: "text/event-stream content type",
				headers: http.Header{
					"Content-Type":   []string{"text/event-stream"},
					"Content-Length": []string{"100"},
				},
				status:   http.StatusOK,
				expected: true,
			},
			{
				name: "application/x-ndjson content type",
				headers: http.Header{
					"Content-Type":   []string{"application/x-ndjson"},
					"Content-Length": []string{"100"},
				},
				status:   http.StatusOK,
				expected: true,
			},
			{
				name: "application/stream+json content type",
				headers: http.Header{
					"Content-Type":   []string{"application/stream+json; charset=utf-8"},
					"Content-Length": []string{"100"},
				},
				status:   http.StatusOK,
				expected: true,
			},
			{
				name: "missing content-length with 200 status",
				headers: http.Header{
					"Content-Type": []string{"text/plain"},
				},
				status:   http.StatusOK,
				expected: true,
			},
			{
				name: "missing content-length with non-200 status",
				headers: http.Header{
					"Content-Type": []string{"text/plain"},
				},
				status:   http.StatusNotFound,
				expected: false,
			},
			{
				name: "regular response with content-length",
				headers: http.Header{
					"Content-Type":   []string{"text/plain"},
					"Content-Length": []string{"9"},
				},
				contentLength: 9,
				status:        http.StatusOK,
				expected:      false,
			},
			{
				name: "json response with content-length",
				headers: http.Header{
					"Content-Type":   []string{"application/json"},
					"Content-Length": []string{"9"},
				},
				contentLength: 9,
				status:        http.StatusOK,
				expected:      false,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				rh, cleanup := doRequest(t, http.MethodGet, "", func(req *http.Request) *http.Response {
					return &http.Response{
						StatusCode:    tc.status,
						Header:        tc.headers,
						Body:          io.NopCloser(bytes.NewReader([]byte("test body"))),
						ContentLength: tc.contentLength,
					}
				})
				defer cleanup()

				isStreaming, err := main.ResponseIsStreaming(rh)
				require.NoError(t, err)
				require.Equal(t, tc.expected, isStreaming)
			})
		}
	})
}

// doRequest is a helper function that performs a request, returning the response
// handle and a cleanup function.
func doRequest(t *testing.T, method, requestBody string, responseFn responseFn) (uintptr, func()) {
	nodes, receivers := newVerifiedNodes(t, 1)
	handler := validHandler(t, receivers, responseFn)
	endpointURL := test.RunHandlerWhile(t, handler)

	ch := newClientForNodes(t, nodes, endpointURL)

	req, err := http.NewRequest(method, url, bytes.NewReader([]byte(requestBody)))
	require.NoError(t, err)

	reqBytes, err := httputil.DumpRequest(req, true)
	require.NoError(t, err)

	rh, err := main.ClientDoRequest(ch, reqBytes)
	require.NoError(t, err)

	cleanup := func() {
		destroyResponse(t, rh)
		destroyClient(t, ch)
	}

	return rh, cleanup
}

func newClientForNodes(t *testing.T, nodes []openpcc.VerifiedNode, endpointURL string) uintptr {
	getOpts := func() []openpcc.Option {
		innerHTTPClient := &http.Client{
			Timeout: 5 * time.Second,
		}
		wallet := &ctest.FakeWallet{
			BeginPaymentFunc: func(ctx context.Context, amount int64) (wallet.Payment, error) {
				return ctest.NewFakePayment(t, amount), nil
			},
		}
		nodeFinder := &ctest.FakeNodeFinder{
			FindVerifiedNodesFunc: func(ctx context.Context, maxNodes int, tags tags.Tags) ([]openpcc.VerifiedNode, error) {
				return nodes, nil
			},
		}
		authClient := &ctest.FakeAuthClient{
			RouterURLFunc: func() string {
				return endpointURL
			},
		}
		return []openpcc.Option{
			openpcc.WithWallet(wallet),
			openpcc.WithVerifiedNodeFinder(nodeFinder),
			openpcc.WithAuthClient(authClient),
			openpcc.WithAnonHTTPClient(innerHTTPClient),
			openpcc.WithRouterPing(false),
			openpcc.WithRouterURL(endpointURL),
		}
	}

	var clientHandle uintptr
	var err error
	main.WithGetOpts(getOpts, func() {
		clientHandle, err = main.ClientCreate("my-api-key", 0, 0, []string{"llm", "model=llama3.2:1b"}, "")
	})
	require.NoError(t, err)
	return clientHandle
}

func destroyClient(t *testing.T, clientHandle uintptr) {
	err := main.ClientDestroy(clientHandle)
	require.NoError(t, err)
}

func destroyResponse(t *testing.T, responseHandle uintptr) {
	err := main.ResponseDestroy(responseHandle)
	require.NoError(t, err)
}

func newVerifiedNodes(t *testing.T, n int) ([]openpcc.VerifiedNode, map[uuid.UUID]*twoway.MultiRequestReceiver) {
	nodes := make([]openpcc.VerifiedNode, 0, n)
	receivers := make(map[uuid.UUID]*twoway.MultiRequestReceiver)

	for i := range n {
		id := test.DeterministicV7UUID(i)
		receiver, computeData := test.NewComputeNodeReceiver(t)
		receivers[id] = receiver
		nodes = append(nodes, openpcc.VerifiedNode{
			Manifest:    routerapi.ComputeManifest{ID: id},
			TrustedData: computeData,
			VerifiedAt:  time.Now(),
		})
	}

	return nodes, receivers
}

type responseFn func(req *http.Request) *http.Response

func validHandler(
	t *testing.T,
	receivers map[uuid.UUID]*twoway.MultiRequestReceiver,
	responseFn responseFn,
) http.Handler {
	candidateHandle := func(w http.ResponseWriter, r *http.Request, candidate routerapi.ComputeCandidate, receiver *twoway.MultiRequestReceiver) {
		req, opener, err := messages.DecapsulateRequest(r.Context(), receiver, candidate.EncapsulatedKey, r.Header.Get("Content-Type"), r.Body)
		require.NoError(t, err)

		sealer, mediaType, err := messages.EncapsulateResponse(opener, responseFn(req))
		require.NoError(t, err)

		// set the picked node id on the response so the client can decrypt it.
		w.Header().Set(routerapi.NodeIDHeader, candidate.ID.String())
		w.Header().Set("Content-Type", mediaType)
		if mediaType == messages.MediaTypeResponseChunked {
			w.Header().Set("Transfer-Encoding", "chunked")
		}
		w.WriteHeader(http.StatusOK)
		_, err = io.Copy(w, sealer)
		require.NoError(t, err)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// simulate router and compute node in this handler.
		var info routerapi.ComputeRequestInfo
		err := info.UnmarshalText([]byte(req.Header.Get(routerapi.RoutingInfoHeader)))
		if err != nil {
			httpfmt.BinaryBadRequest(w, req, "invalid routing info")
			return
		}

		body, err := io.ReadAll(req.Body)
		if err != nil {
			httpfmt.BinaryServerError(w, req)
			return
		}

		// pick a random candidate to write the actual response request.
		i := mathrand.IntN(len(info.Candidates))
		candidate := info.Candidates[i]
		receiver, ok := receivers[candidate.ID]
		if !ok {
			httpfmt.BinaryError(w, req, "unknown target node", http.StatusNotFound)
			return
		}

		req.Body = io.NopCloser(bytes.NewReader(body)) // candidateHandle consumes the body
		candidateHandle(w, req, candidate, receiver)
	})

	return h
}
