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
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
*/
import "C"

import (
	"bufio"
	"sync"

	"github.com/openpcc/openpcc/messages"
)

const (
	// defaultChunkSize is the default size of the chunks that the response stream will
	// read from the response body if the data is not being streamed in NDJSON format.
	// This matches [messages.MaxChunkLen] since anything larger is too big.
	defaultChunkSize = messages.UserChunkLen
)

var (
	streamsRegistry = newRegistry[responseStream]()
)

// Confsec_ResponseStreamGetNext returns the next chunk of data from the response stream
// associated with the given handle. If there is no more data, it returns NULL.
//
//export Confsec_ResponseStreamGetNext
func Confsec_ResponseStreamGetNext(handle C.uintptr_t, errStr **C.char) *C.char { //nolint:revive
	stream := streamsRegistry.get(uintptr(handle))
	if stream == nil {
		setError(errStr, ErrResponseStreamNotFound)
		return nil
	}

	stream.mu.Lock()
	defer stream.mu.Unlock()

	if stream.done {
		return nil
	}

	hasNext := stream.scanner.Scan()
	// Check for any errors that occurred while scanning. We don't need special handling
	// for EOF because Scan handles it internally and returns false.
	err := stream.scanner.Err()
	if err != nil {
		setError(errStr, err)
		return nil
	}

	if !hasNext {
		// No more data - close stream and mark as done
		stream.resp.close()
		stream.done = true
		return nil
	}

	chunk := stream.scanner.Text()
	return C.CString(chunk)
}

// Confsec_ResponseStreamDestroy safely destroys the response stream associated with the
// given handle.
//
//export Confsec_ResponseStreamDestroy
func Confsec_ResponseStreamDestroy(handle C.uintptr_t, errStr **C.char) { //nolint:revive
	stream := streamsRegistry.get(uintptr(handle))
	if stream == nil {
		setError(errStr, ErrResponseStreamNotFound)
		return
	}

	stream.resp.close()
	streamsRegistry.remove(uintptr(handle))
}

// response is a wrapper around [response] that provides a streaming interface over.
// the response body.
type responseStream struct {
	mu      sync.Mutex
	resp    *response
	scanner *bufio.Scanner
	done    bool
}

// newResponseStream creates a new responseStream for the given response. It is assumed
// that the caller has already validated that the response is a streaming response, but
// the responseStream should still work in either case.
func newResponseStream(resp *response) *responseStream {
	scanner := bufio.NewScanner(resp.resp.Body)
	// By default, bufio.Scanner will split the input into lines. However, we want to
	// split the input into chunks of a fixed size, without modifying the underlying
	// response body, so we use a custom split function.
	scanner.Split(scanChunk)

	return &responseStream{
		resp:    resp,
		scanner: scanner,
		done:    false,
	}
}

// scanChunk is a custom split function for bufio.Scanner that reads chunks of data of
// a fixed size [defaultChunkSize] from the input.
func scanChunk(data []byte, atEOF bool) (int, []byte, error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	// If we have a full chunk, return it
	if len(data) >= defaultChunkSize {
		return defaultChunkSize, data[:defaultChunkSize], nil
	}

	// If we're at EOF, return whatever remaining data we have
	if atEOF {
		return len(data), data, nil
	}

	// Request more data by returning 0 advance with no token
	return 0, nil, nil
}
