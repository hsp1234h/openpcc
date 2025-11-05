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

package httpfmt_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openpcc/openpcc/httpfmt"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type okBinary struct {
	data []byte
}

func (o *okBinary) UnmarshalBinary(b []byte) error {
	o.data = b
	return nil
}

func (o *okBinary) MarshalBinary() ([]byte, error) {
	return o.data, nil
}

type failBinary struct{}

func (f *failBinary) UnmarshalBinary([]byte) error {
	return assert.AnError
}

func (f *failBinary) MarshalBinary() ([]byte, error) {
	return nil, assert.AnError
}

func TestBinaryHandler(t *testing.T) {
	newReq := func(data []byte) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/octet-stream")
		return req
	}

	t.Run("ok", func(t *testing.T) {
		h := httpfmt.BinaryHandler(func(ctx context.Context, in *okBinary) (*okBinary, error) {
			require.Equal(t, []byte("abcde"), in.data)
			return &okBinary{
				data: []byte("fghij"),
			}, nil
		})

		req := newReq([]byte("abcde"))
		rr := httptest.NewRecorder()

		h.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Equal(t, res.Header.Get("Content-Type"), "application/octet-stream")
		require.Equal(t, res.Header.Get("Content-Length"), "5")
		test.RequireReadAll(t, []byte("fghij"), res.Body)
	})

	t.Run("fail, wrong content-type", func(t *testing.T) {
		h := httpfmt.BinaryHandler(func(ctx context.Context, in *okBinary) (*okBinary, error) {
			return &okBinary{}, nil
		})

		req := newReq([]byte(""))
		req.Header.Set("Content-Type", "text/plain")
		rr := httptest.NewRecorder()

		h.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("fail, error unmarshalling request body", func(t *testing.T) {
		h := httpfmt.BinaryHandler(func(ctx context.Context, in *failBinary) (*okBinary, error) {
			return &okBinary{}, nil
		})

		req := newReq([]byte(""))
		rr := httptest.NewRecorder()

		h.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("fail, error from target func", func(t *testing.T) {
		h := httpfmt.BinaryHandler(func(ctx context.Context, in *okBinary) (*okBinary, error) {
			return &okBinary{}, errors.New("failed to do xyz")
		})

		req := newReq([]byte(""))
		rr := httptest.NewRecorder()

		h.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusInternalServerError, res.StatusCode)
	})

	t.Run("fail, error marshalling response body", func(t *testing.T) {
		h := httpfmt.BinaryHandler(func(ctx context.Context, in *okBinary) (*failBinary, error) {
			return &failBinary{}, nil
		})

		req := newReq([]byte(""))
		rr := httptest.NewRecorder()

		h.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusInternalServerError, res.StatusCode)
	})
}
