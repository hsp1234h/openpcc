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
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
)

const (
	versionLen = 1
	idLen      = 16
	indexLen   = 4
	finalLen   = 1
	headerLen  = versionLen + idLen + indexLen + finalLen // [ProtoVersion][Message ID][Message Index][Final]

	// version is the current version of the broadcasting encoder.
	version = 1

	finalChunk = 1
)

// broadcaster is a helper struct that splits messages into chunks.
//
// The chunks can then reassembled by receiver to get the original message.
type broadcaster struct {
	idFunc func([]byte) error
	mu     sync.RWMutex

	// backlog contains the backlog of full messages we need to chunk & broadcast.
	backlog [][]byte

	currentMsgID [idLen]byte
	currentIndex uint32
	currentMsg   []byte
}

func newBroadcaster() *broadcaster {
	return &broadcaster{
		idFunc: func(b []byte) error {
			_, err := rand.Read(b)
			return err
		},
		mu:      sync.RWMutex{},
		backlog: make([][]byte, 0),
	}
}

// message schedules a message to be broadcast.
func (c *broadcaster) message(msg []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.backlog = append(c.backlog, msg)
}

// chunks takes messages from the backlog and splits them into chunks if necessary.
func (c *broadcaster) chunks(overhead int, limit int) ([][]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var chunks [][]byte
	total := 0
	for total < limit {
		if len(c.currentMsg) == 0 {
			if len(c.backlog) == 0 {
				break
			}

			err := c.nextMessage()
			if err != nil {
				return chunks, nil
			}
		}

		// maxB nr of bytes we can possibly store in a chunk considering
		// the overall limit, membership overhead and chunk header overhead.
		maxB := limit - total - overhead - headerLen
		if maxB <= 0 {
			// no space left for any data.
			break
		}

		chunk := c.messageChunk(maxB)
		chunks = append(chunks, chunk)
		total += overhead + len(chunk)
	}

	return chunks, nil
}

func (c *broadcaster) nextMessage() error {
	// get new message from backlog
	err := c.idFunc(c.currentMsgID[:])
	if err != nil {
		return fmt.Errorf("failed to generate ID: %w", err)
	}
	c.currentIndex = 0
	c.currentMsg = c.backlog[0]
	c.backlog = c.backlog[1:]
	return nil
}

func (c *broadcaster) messageChunk(maxLen int) []byte {
	n := maxLen
	final := byte(0)
	if len(c.currentMsg) <= maxLen {
		n = len(c.currentMsg)
		final = finalChunk
	}

	// create the chunk
	chunk := make([]byte, headerLen, headerLen+n)
	c.writeHeader(chunk, final)
	chunk = append(chunk, c.currentMsg[:n]...)

	// consume current message
	c.currentMsg = c.currentMsg[n:]
	c.currentIndex++

	return chunk
}

func (c *broadcaster) writeHeader(b []byte, final byte) {
	idEnd := idLen + versionLen
	indexEnd := idEnd + indexLen

	b[0] = version
	copy(b[versionLen:idEnd], c.currentMsgID[:])
	binary.BigEndian.PutUint32(b[idEnd:indexEnd], c.currentIndex)
	b[indexEnd] = final
}
