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
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// JSON writes the data as a JSON response with the given status code.
func JSON(w http.ResponseWriter, r *http.Request, data any, code int) {
	body, err := json.Marshal(data)
	if err != nil {
		slog.ErrorContext(r.Context(), "error marshalling json response", "error", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	_, err = w.Write(body)
	if err != nil {
		slog.ErrorContext(r.Context(), "error writing json response", "error", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
}

// JSONError is a convenience function that writes a json error response.
func JSONError(w http.ResponseWriter, r *http.Request, msg string, code int) {
	type body struct {
		Error string `json:"error"`
	}

	// Mark span from calling function as errored.
	span := trace.SpanFromContext(r.Context())
	span.SetStatus(codes.Error, msg)

	JSON(w, r, body{Error: msg}, code)
}

// JSONBadRequest is a convenience function that returns a status 400 response.
func JSONBadRequest(w http.ResponseWriter, r *http.Request, msg string) {
	JSONError(w, r, msg, http.StatusBadRequest)
}

// JSONServerError is a convenience function that returns a status 500 response
// without exposing error information to the client.
func JSONServerError(w http.ResponseWriter, r *http.Request) {
	JSONError(w, r, "internal server error", http.StatusInternalServerError)
}

// JSONHealthCheck is a convenience function that writes a status 200 healthcheck response.
// useful for simple services that don't have dependencies.
func JSONHealthCheck(w http.ResponseWriter, r *http.Request) {
	type body struct {
		Status string `json:"status"`
	}

	JSON(w, r, body{Status: "OK"}, http.StatusOK)
}

// DecodeJSONError is a convenience function that decodes a binary error.
func DecodeJSONErrorAsError(r io.Reader) (error, error) {
	type body struct {
		Error string `json:"error"`
	}

	tgt := body{}
	dec := json.NewDecoder(r)
	err := dec.Decode(&tgt)
	if err != nil {
		return nil, err
	}

	return errors.New(tgt.Error), nil
}
