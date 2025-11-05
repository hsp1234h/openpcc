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

package gossip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"maps"
	"sync"
	"time"
)

type receiver struct {
	mu      sync.Mutex
	nowFunc func() time.Time

	messages map[string]chunkedMsg
}

func newReceiver() *receiver {
	return &receiver{
		mu:       sync.Mutex{},
		nowFunc:  time.Now,
		messages: map[string]chunkedMsg{},
	}
}

// receiveChunk parses the chunk and adds it to the open messages
// if this chunk completes a message, the message will be returned
// as the first return value.
//
// receiver keeps an internal copy of b, it is safe to modify b after
// receiveChunk has returned.
func (r *receiver) receiveChunk(b []byte) ([]byte, error) {
	chnk, err := parseChunk(b)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	msg, ok := r.messages[chnk.msgID]
	if !ok {
		msg = chunkedMsg{
			chunks:    map[uint32][]byte{},
			createdAt: r.nowFunc(),
		}
	}

	// check if we received a duplicate chunk and this message has
	// already been received before.
	if msg.isComplete() {
		return nil, nil
	}

	msg.chunks[chnk.index] = chnk.data
	if chnk.final == finalChunk {
		msg.finalIndex = &chnk.index
	}
	msg.msgLen += len(chnk.data)

	r.messages[chnk.msgID] = msg

	if msg.isComplete() {
		return msg.bytes(), nil
	}

	return nil, nil
}

func (r *receiver) cleanup(maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	limit := r.nowFunc().Add(-maxAge)

	maps.DeleteFunc(r.messages, func(_ string, v chunkedMsg) bool {
		return v.createdAt.Before(limit)
	})
}

type chunkedMsg struct {
	chunks     map[uint32][]byte
	finalIndex *uint32
	msgLen     int
	createdAt  time.Time
}

func (m *chunkedMsg) isComplete() bool {
	if m.finalIndex == nil {
		return false
	}

	for i := uint32(0); i <= *m.finalIndex; i++ {
		_, ok := m.chunks[i]
		if !ok {
			return false
		}
	}

	return true
}

func (m *chunkedMsg) bytes() []byte {
	if m.finalIndex == nil {
		return nil
	}

	out := make([]byte, 0, m.msgLen)
	for i := uint32(0); i <= *m.finalIndex; i++ {
		data, ok := m.chunks[i]
		if !ok {
			return nil
		}
		out = append(out, data...)
	}

	return out
}

type chunk struct {
	msgID string
	index uint32
	final byte
	data  []byte
}

func parseChunk(raw []byte) (*chunk, error) {
	if len(raw) <= headerLen {
		return nil, fmt.Errorf("expected a chunk of more than %d bytes, got %d", headerLen, len(raw))
	}

	if raw[0] != version {
		return nil, fmt.Errorf("can only parse chunks of version %d, got %d", version, raw[0])
	}

	// create the receiver copy
	b := bytes.Clone(raw)

	idEnd := idLen + versionLen
	indexEnd := idEnd + indexLen

	return &chunk{
		msgID: string(b[versionLen : versionLen+idLen]),
		index: binary.BigEndian.Uint32(b[idEnd:indexEnd]),
		final: b[indexEnd],
		data:  b[headerLen:],
	}, nil
}
