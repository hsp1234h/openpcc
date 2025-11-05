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

package proton

import (
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

// Decoder provides functionality to decode protocol buffer messages from an io.Reader.
type Decoder struct {
	r io.Reader
}

// NewDecoder creates a new Decoder that reads from the provided io.Reader.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: r}
}

// Decode reads the next protocol buffer message from its reader and stores it in
// the provided message. The message must be a non-nil pointer to a protocol buffer message.
func (d *Decoder) Decode(message proto.Message) error {
	body, err := io.ReadAll(d.r)
	if err != nil {
		return fmt.Errorf("failed to read message: %w", err)
	}

	if err := proto.Unmarshal(body, message); err != nil {
		return fmt.Errorf("failed to unmarshal message: %w", err)
	}

	return nil
}
