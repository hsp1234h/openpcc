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

// cshttptest contians confsec specific http testing functionality.
//
// "cs" ("confsec") prefix added to prevent shadowing the stdlib net/http/httptest package.
package cshttptest

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func HeaderSectionOnly(httpMsg string) string {
	// find start of body
	bodyStart := strings.Index(httpMsg, "\r\n\r\n") + 4
	return httpMsg[:bodyStart]
}

func CutHeaderSection(httpMsg string) string {
	// find start of body
	bodyStart := strings.Index(httpMsg, "\r\n\r\n") + 4
	return httpMsg[bodyStart:]
}

// ParseBodyChunksFromMessage parses the body chunks of a HTTP body in a simplified manner.
// It does not support chunk extensions for example.
func ParseBodyChunks(body string) ([][]byte, error) {
	r := bufio.NewReader(strings.NewReader(body))
	var out [][]byte
	for {
		lenLine, err := r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("unexpected error: %w", err)
		}

		lenLine = strings.TrimSpace(lenLine)
		if lenLine == "" {
			continue
		}

		// Parse the hex size
		chunkLen, err := strconv.ParseInt(lenLine, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid chunk length: %w", err)
		}

		chunk := make([]byte, chunkLen)
		_, err = io.ReadFull(r, chunk)
		if err != nil {
			return nil, fmt.Errorf("failed to read chunk: %w", err)
		}
		out = append(out, chunk)
		// skip \r\n
		skipBytes := 2
		for skipBytes > 0 {
			_, err := r.ReadByte()
			if err != nil {
				break
			}
			skipBytes--
		}
	}

	lastChunkLen := len(out[len(out)-1])
	if lastChunkLen != 0 {
		return nil, fmt.Errorf("expected the last chunk to be zero, got %d", lastChunkLen)
	}

	// drop that last zero sized chunk.
	return out[:len(out)-1], nil
}
