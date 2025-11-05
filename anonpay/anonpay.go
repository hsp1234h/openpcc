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

package anonpay

import (
	"context"
	"crypto/rand"
	"encoding"
	"math/big"

	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/gen/protos"
)

// RandFloat64 returns a random float64 in the range [0.0, 1.0).
func RandFloat64() (float64, error) {
	i, err := rand.Int(rand.Reader, big.NewInt(1<<53))
	if err != nil {
		return 0, err
	}
	return float64(i.Int64()) / (1 << 53), nil
}

// NonceLocker locks, consumed and/or releases currency nonces while transactions are in flight.
//
// Anonpay requires a centralized nonce locking service to prevent double spend of credits.
//
// Nonces don't need to be stored indefinitely by a nonce locking service; instead they can be removed
// after their expiry to prevent the stored data growing indefinitely.
type NonceLocker interface {
	// CheckAndLockNonce checks if the nonce is unconsumed and locks it if it is.
	//
	// To conform to this contract, implementations:
	// - Must return an [InputError] if the nonce has expired when it is received.
	// - Must return an [InputError] if the nonce data is not of [NonceLen].
	// - Must return [ErrNonceConsumed] if the nonce has already consumed when [CheckAndLockNonce] is called. This
	//   error should be returned until the nonce has expired.
	// - Must return [ErrNonceLocked] if the nonce is locked when [CheckAndLockNonce] was called.
	// - Must ensure nonces can only be consumed once.
	// - Must ensure released nonce can be locked again.
	// - May delete stored state belonging to expired nonces.
	CheckAndLockNonce(ctx context.Context, nonce Nonce) (LockedNonce, error)
}

// LockedNonce is a storage independent representation of a locked nonce.
type LockedNonce interface {
	// Consume marks the nonce as used.
	Consume(ctx context.Context) error
	// Release releases the lock and allows the nonce to be used again.
	//
	// Implementations should make sure that it is safe to call Release on a LockedNonce that has already
	// been consumed by a call to Consume, allowing users to defer the Release.
	Release(ctx context.Context) error
}

// AnyCredit is either a credit or an unblinded credit.
type AnyCredit interface {
	Value() currency.Value
	Nonce() Nonce
	Signature() []byte

	encoding.TextMarshaler
	encoding.TextUnmarshaler

	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler

	MarshalProto() (*protos.Credit, error)
	UnmarshalProto(credit *protos.Credit) error
}
