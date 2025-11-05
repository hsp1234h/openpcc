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

package inttest

import (
	"context"
	"errors"
	"sync"

	"github.com/openpcc/openpcc/anonpay"
)

type NoopNonceLocker struct {
	mu         *sync.Mutex
	usedNonces map[[anonpay.NonceLen]byte]int
}

func NewNoopNonceLocker() *NoopNonceLocker {
	return &NoopNonceLocker{
		mu:         &sync.Mutex{},
		usedNonces: make(map[[16]byte]int),
	}
}

type noopNonceLock struct {
	locker *NoopNonceLocker
	key    [anonpay.NonceLen]byte
}

func (n *NoopNonceLocker) CheckAndLockNonce(_ context.Context, nonce anonpay.Nonce) (anonpay.LockedNonce, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if _, ok := n.usedNonces[[anonpay.NonceLen]byte(nonce.Nonce)]; ok {
		return nil, anonpay.ErrNonceConsumed
	}
	n.usedNonces[[anonpay.NonceLen]byte(nonce.Nonce)] = 1 // Locked
	return noopNonceLock{
		locker: n,
		key:    [anonpay.NonceLen]byte(nonce.Nonce),
	}, nil
}

func (n noopNonceLock) Ticket() string {
	return ""
}

func (n noopNonceLock) Consume(_ context.Context) error {
	n.locker.mu.Lock()
	defer n.locker.mu.Unlock()

	//nolint:unconvert
	n.locker.usedNonces[[anonpay.NonceLen]byte(n.key)] = 2 // Consumed
	return nil
}

func (n noopNonceLock) Release(_ context.Context) error {
	n.locker.mu.Lock()
	defer n.locker.mu.Unlock()

	state, ok := n.locker.usedNonces[n.key]
	if !ok {
		return errors.New("nonce not locked")
	}
	if state == 2 {
		return nil // Already consumed is not an error to allow for defer lock.Release() pattern like defer tx.Rollback()
	}
	delete(n.locker.usedNonces, n.key)
	return nil
}
