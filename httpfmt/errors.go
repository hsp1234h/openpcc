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

package httpfmt

import (
	"errors"
	"io"
	"net/http"
)

// ParseBodyAsError attempts to parse an error from the request body
// and adds those errors to the original error. ParseBodyAsError closes
// the request body.
func ParseBodyAsError(resp *http.Response, err error) error {
	const maxErrorBytes = 4096
	defer resp.Body.Close()

	// limit how much we will read, in case some service
	// returns excessively large errors.
	reader := io.LimitReader(resp.Body, maxErrorBytes)

	switch resp.Header.Get("Content-Type") {
	case "application/json":
		causeErr, decErr := DecodeJSONErrorAsError(reader)
		return errors.Join(err, causeErr, decErr)
	case "application/octet-stream":
		causeErr, decErr := DecodeBinaryErrorAsError(reader)
		return errors.Join(err, causeErr, decErr)
	default:
		bdy, readErr := io.ReadAll(reader)
		causeErr := errors.New(string(bdy))
		return errors.Join(err, causeErr, readErr)
	}
}

// ErrorWithStatusCode indicates a generic handler should return a
// specific status code for this error.
type ErrorWithStatusCode struct {
	Err           error
	StatusCode    int
	PublicMessage string
}

func (e ErrorWithStatusCode) Error() string {
	return e.Err.Error()
}

func (e ErrorWithStatusCode) Unwrap() error {
	return e.Err
}
