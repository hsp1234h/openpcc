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
	"context"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"github.com/hashicorp/memberlist"
	"github.com/openpcc/openpcc/uuidv7"
)

type MessageHandler interface {
	HandleMessage(ctx context.Context, msg []byte)
}

type StateHandler interface {
	HandleState(ctx context.Context, state []byte)
}

type StateReader interface {
	ReadState(ctx context.Context) []byte
}

type NodeHandler interface {
	HandleNodeJoin(ctx context.Context, id uuid.UUID, b []byte)
	HandleNodeLeave(ctx context.Context, id uuid.UUID, b []byte)
}

// delegate is a memberlist.Delegate that maps calls to handlers/readers.
type delegate struct {
	localID   uuid.UUID
	localMeta []byte

	broadcaster *broadcaster
	receiver    *receiver

	// handlers
	handlersWG *sync.WaitGroup

	messageHandler MessageHandler
	stateHandler   StateHandler
	stateReader    StateReader
	nodeHandler    NodeHandler
}

func newDelegate(id uuid.UUID) *delegate {
	return &delegate{
		localID:     id,
		broadcaster: newBroadcaster(),
		receiver:    newReceiver(),
		handlersWG:  &sync.WaitGroup{},
	}
}

func (d *delegate) BroadcastMessage(msg []byte) {
	d.broadcaster.message(msg)
}

// NodeMeta is used to retrieve meta-data about the current node
// when broadcasting an alive message. It's length is limited to
// the given byte size. This metadata is available in the Node structure.
func (d *delegate) NodeMeta(_ int) []byte {
	return d.localMeta
}

// NotifyJoin is invoked when a node is detected to have joined.
// The Node argument must not be modified.
func (d *delegate) NotifyJoin(n *memberlist.Node) {
	if d.nodeHandler == nil {
		return
	}

	id, err := uuidv7.Parse(n.Name)
	if err != nil {
		slog.Error("node joined with a non uuidv7 name", "error", err)
		return
	}

	if id == d.localID {
		return
	}

	d.nodeHandler.HandleNodeJoin(context.Background(), id, bytes.Clone(n.Meta))
}

// NotifyLeave is invoked when a node is detected to have left.
// The Node argument must not be modified.
func (d *delegate) NotifyLeave(n *memberlist.Node) {
	if d.nodeHandler == nil {
		return
	}

	id, err := uuidv7.Parse(n.Name)
	if err != nil {
		slog.Error("node left with a non uuidv7 name", "error", err)
		return
	}

	if id == d.localID {
		return
	}

	d.nodeHandler.HandleNodeLeave(context.Background(), id, bytes.Clone(n.Meta))
}

// NotifyUpdate is invoked when a node is detected to have
// updated, usually involving the meta data. The Node argument
// must not be modified.
func (*delegate) NotifyUpdate(_ *memberlist.Node) {
	// Required to implement the memberlist.EventDelegate, but no-op
	// as our nodes don't update their metadata.
}

// NotifyMsg is called when a user-data message is received.
// Care should be taken that this method does not block, since doing
// so would block the entire UDP packet receive loop. Additionally, the byte
// slice may be modified after the call returns, so it should be copied if needed.
func (d *delegate) NotifyMsg(msg []byte) {
	if d.messageHandler == nil {
		return
	}

	// TODO (optimization): The receiver can block as it uses a mutex internally, we should
	// probably use a buffered channel and drop messages if the channel is
	// full.
	fullMsg, err := d.receiver.receiveChunk(msg)
	if err != nil {
		slog.Error("received malformed chunk", "error", err)
		return
	}

	if len(fullMsg) == 0 {
		return
	}

	// handle the message in a separate goroutine, so this doesn't block further.
	d.handlersWG.Add(1)
	go func() {
		defer d.handlersWG.Done()
		d.messageHandler.HandleMessage(context.Background(), fullMsg)
	}()
}

// GetBroadcasts is called when user data messages can be broadcast.
// It can return a list of buffers to send. Each buffer should assume an
// overhead as provided with a limit on the total byte size allowed.
// The total byte size of the resulting data to send must not exceed
// the limit. Care should be taken that this method does not block,
// since doing so would block the entire UDP packet receive loop.
func (d *delegate) GetBroadcasts(overhead int, limit int) [][]byte {
	// TODO (optimization): The broadcaster can block as it uses a mutex internally, we should
	// probably use a buffered channel and block on the broadcasting end when it's full.
	chunks, err := d.broadcaster.chunks(overhead, limit)
	if err != nil {
		slog.Error("failed to chunk messages", "err", err)
		return nil
	}

	return chunks
}

// LocalState is used for a TCP Push/Pull. This is sent to
// the remote side in addition to the membership information. Any
// data can be sent here. See MergeRemoteState as well. The `join`
// boolean indicates this is for a join instead of a push/pull.
func (d *delegate) LocalState(_ bool) []byte {
	if d.stateReader == nil {
		return nil
	}

	return d.stateReader.ReadState(context.Background())
}

// MergeRemoteState is invoked after a TCP Push/Pull. This is the
// state received from the remote side and is the result of the
// remote side's LocalState call. The 'join'
// boolean indicates this is for a join instead of a push/pull.
func (d *delegate) MergeRemoteState(buf []byte, _ bool) {
	if d.stateHandler == nil {
		return
	}
	d.stateHandler.HandleState(context.Background(), buf)
}

func (d *delegate) Close() error {
	d.handlersWG.Wait()
	return nil
}
