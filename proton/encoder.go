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

// Encoder provides functionality to encode protocol buffer messages to an io.Writer.
type Encoder struct {
	w io.Writer
}

// NewEncoder creates a new Encoder that writes to the provided io.Writer.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// Encode writes the protocol buffer message to its writer.
func (e *Encoder) Encode(message proto.Message) error {
	data, err := proto.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	if _, err := e.w.Write(data); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}
