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

package main

/*
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
*/
import "C"

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

var (
	responsesRegistry = newRegistry[response]()
)

// Confsec_ResponseDestroy safely destroys the response object associated with the given
// handle.
//
//export Confsec_ResponseDestroy
func Confsec_ResponseDestroy(handle C.uintptr_t, errStr **C.char) { //nolint:revive
	resp := responsesRegistry.get(uintptr(handle))
	if resp == nil {
		setError(errStr, ErrResponseNotFound)
		return
	}

	resp.close()
	responsesRegistry.remove(uintptr(handle))
}

// Confsec_ResponseGetMetadata returns the metadata associated with the response object
// associated with the given handle. This includes the start line and HTTP headers. The
// metadata is returned as a stringified JSON object.
//
//export Confsec_ResponseGetMetadata
func Confsec_ResponseGetMetadata(handle C.uintptr_t, errStr **C.char) *C.char { //nolint:revive
	resp := responsesRegistry.get(uintptr(handle))
	if resp == nil {
		setError(errStr, ErrResponseNotFound)
		return nil
	}

	b, err := resp.getMetadata()
	if err != nil {
		setError(errStr, err)
		return nil
	}

	return C.CString(b)
}

// Confsec_ResponseIsStreaming returns true if the response object associated with the
// given handle is a streaming response.
//
//export Confsec_ResponseIsStreaming
func Confsec_ResponseIsStreaming(handle C.uintptr_t, errStr **C.char) C.bool { //nolint:revive
	resp := responsesRegistry.get(uintptr(handle))
	if resp == nil {
		setError(errStr, ErrResponseNotFound)
		return C.bool(false)
	}

	if resp.isStreaming() {
		return C.bool(true)
	}

	return C.bool(false)
}

// Confsec_ResponseGetBody returns the body of the response object associated with the
// given handle. The body is returned as a null-terminated byte array. If the response
// has Transfer-Encoding: chunked, calling this function results in an error.
//
//export Confsec_ResponseGetBody
func Confsec_ResponseGetBody(handle C.uintptr_t, errStr **C.char) *C.char { //nolint:revive
	resp := responsesRegistry.get(uintptr(handle))
	if resp == nil {
		setError(errStr, ErrResponseNotFound)
		return nil
	}

	if resp.isStreaming() {
		setError(errStr, ErrResponseIsStreaming)
		return nil
	}

	body, err := io.ReadAll(resp.resp.Body)
	if err != nil {
		setError(errStr, err)
		return nil
	}

	if body == nil {
		return nil
	}

	return C.CString(string(body))
}

// Confsec_ResponseGetStream returns a handle to a stream object that can be used to
// read the response body in chunks. If the response is not a streaming response, (i.e.
// it has Transfer-Encoding: chunked), then calling this function results in an error.
//
//export Confsec_ResponseGetStream
func Confsec_ResponseGetStream(handle C.uintptr_t, errStr **C.char) C.uintptr_t { //nolint:revive
	resp := responsesRegistry.get(uintptr(handle))
	if resp == nil {
		setError(errStr, ErrResponseNotFound)
		return C.uintptr_t(0)
	}

	if !resp.isStreaming() {
		setError(errStr, ErrResponseIsNotStreaming)
		return C.uintptr_t(0)
	}

	stream := newResponseStream(resp)
	id := streamsRegistry.add(stream)

	return C.uintptr_t(id)
}

// KV is just a simple key-value pair
type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ResponseMetadata contains the metadata associated with an HTTP response
type ResponseMetadata struct {
	StatusCode   int    `json:"status_code"`
	ReasonPhrase string `json:"reason_phrase"`
	HTTPVersion  string `json:"http_version"`
	URL          string `json:"url"`
	Headers      []KV   `json:"headers"`
}

// response is a wrapper around an HTTP response that represents a logical response
// that can be interacted with via the C API.
type response struct {
	mu   sync.RWMutex
	resp *http.Response
}

// isStreaming returns true if the response is a streaming response, false otherwise.
func (r *response) isStreaming() bool {
	// Check Transfer-Encoding for chunked (case-insensitive)
	if strings.Contains(strings.ToLower(r.resp.Header.Get("Transfer-Encoding")), "chunked") {
		return true
	}

	// Check for streaming content types
	contentType := strings.ToLower(r.resp.Header.Get("Content-Type"))
	streamingTypes := []string{
		"text/event-stream",
		"application/x-ndjson",
		"application/stream+json",
	}
	for _, streamType := range streamingTypes {
		if strings.Contains(contentType, streamType) {
			return true
		}
	}

	// Missing Content-Length with specific status codes (like 200) may indicate streaming
	contentLength := r.resp.Header.Get("Content-Length")
	if contentLength == "" && r.resp.StatusCode == http.StatusOK {
		return true
	}

	return false
}

// getMetadata returns the response metadata as JSON string.
func (r *response) getMetadata() (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	url := ""
	if r.resp.Request != nil {
		url = r.resp.Request.URL.String()
	}

	// Estimate the number of headers as the number of distinct header names. This will
	// usually be correct and not require any resizes.
	headers := make([]KV, 0, len(r.resp.Header))
	for k := range r.resp.Header {
		for _, v := range r.resp.Header.Values(k) {
			headers = append(headers, KV{Key: k, Value: v})
		}
	}

	rm := ResponseMetadata{
		StatusCode:   r.resp.StatusCode,
		ReasonPhrase: r.resp.Status,
		HTTPVersion:  r.resp.Proto,
		URL:          url,
		Headers:      headers,
	}

	b, err := json.Marshal(rm)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// close closes the response body.
func (r *response) close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	_ = r.resp.Body.Close()
}
