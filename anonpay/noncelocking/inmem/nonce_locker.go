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

package inmem

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/openpcc/openpcc/anonpay"
)

type nonceStatus string

const (
	statusLocked   nonceStatus = "LOCKED"
	statusConsumed nonceStatus = "CONSUMED"
)

// CreditHole is a service that locks and tracks credit nonces.
type NonceLocker struct {
	mu         *sync.Mutex
	nonces     map[string]storedNonce
	randReader io.Reader
}

type storedNonce struct {
	status nonceStatus
	ticket string
}

// NewNonceLocker returns an in memory nonce locker.
func NewNonceLocker() *NonceLocker {
	return NewNonceLockerWithRandReader(rand.Reader)
}

// NewNonceLocketWithRandReader returns an in-memory nonce locker that
// used the provided reader to generate tickets.
func NewNonceLockerWithRandReader(r io.Reader) *NonceLocker {
	return &NonceLocker{
		mu:         &sync.Mutex{},
		nonces:     make(map[string]storedNonce),
		randReader: r,
	}
}

func (l *NonceLocker) LockNonce(ctx context.Context, nonce anonpay.Nonce) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(nonce.Nonce) != anonpay.NonceLen {
		return "", anonpay.InputError{
			Err: errors.New("invalid nonce length"),
		}
	}

	if nonce.IsExpiredAt(time.Now()) {
		return "", anonpay.InputError{
			Err: errors.New("expired nonce"),
		}
	}

	key := hex.EncodeToString(nonce.Nonce)
	sn, ok := l.nonces[key]
	if ok {
		if sn.status == statusLocked {
			return "", anonpay.ErrNonceLocked
		}
		return "", anonpay.ErrNonceConsumed
	}

	ticketB := make([]byte, 8)
	_, err := io.ReadFull(l.randReader, ticketB)
	if err != nil {
		return "", fmt.Errorf("failed to read ticket: %w", err)
	}

	ticket := hex.EncodeToString(ticketB)
	l.nonces[key] = storedNonce{
		status: statusLocked,
		ticket: ticket,
	}
	return ticket, nil
}

func (l *NonceLocker) ConsumeNonce(ctx context.Context, nonce anonpay.Nonce, ticket string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(nonce.Nonce) != anonpay.NonceLen {
		return anonpay.InputError{
			Err: errors.New("invalid nonce length"),
		}
	}

	key := hex.EncodeToString(nonce.Nonce)
	sn, ok := l.nonces[key]
	if !ok {
		return fmt.Errorf("no lock found for ticket: %s", ticket)
	}

	if sn.status == statusConsumed {
		return anonpay.ErrNonceConsumed
	}

	l.nonces[key] = storedNonce{
		status: statusConsumed,
		ticket: ticket,
	}

	return nil
}

func (l *NonceLocker) ReleaseNonce(ctx context.Context, nonce anonpay.Nonce, ticket string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(nonce.Nonce) != anonpay.NonceLen {
		return anonpay.InputError{
			Err: errors.New("invalid nonce length"),
		}
	}

	key := hex.EncodeToString(nonce.Nonce)
	sn, ok := l.nonces[key]
	if !ok {
		return fmt.Errorf("no lock found for ticket: %s", ticket)
	}

	if sn.status == statusConsumed {
		return anonpay.ErrNonceConsumed
	}

	// released
	delete(l.nonces, key)

	return nil
}

type lockedNonce struct {
	ticket   string
	callback func(release bool)
}

func (n *lockedNonce) Ticket() string {
	return n.ticket
}

func (n *lockedNonce) Consume(ctx context.Context) error {
	n.callback(true)
	return nil
}

func (n *lockedNonce) Release(ctx context.Context) error {
	n.callback(false)
	return nil
}
