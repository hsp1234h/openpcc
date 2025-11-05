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

package testcontract

import (
	"testing"
	"time"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/noncelocking"
	"github.com/stretchr/testify/require"
)

type SetupFunc func(t *testing.T) (noncelocking.TicketLockerContract, time.Duration, error)

func TestTicketLockerContract(t *testing.T, setupFunc SetupFunc) {
	setup := func(t *testing.T) (noncelocking.TicketLockerContract, time.Duration) {
		t.Helper()

		locker, expiration, err := setupFunc(t)
		require.NoError(t, err)

		return locker, expiration
	}

	t.Run("Locking", func(t *testing.T) {
		RunLockingTests(t, setup)
	})

	t.Run("Consuming", func(t *testing.T) {
		RunConsumingTests(t, setup)
	})

	t.Run("Releasing", func(t *testing.T) {
		RunReleasingTests(t, setup)
	})
}

type fullSetupFunc func(t *testing.T) (noncelocking.TicketLockerContract, time.Duration)

func RunLockingTests(t *testing.T, setup fullSetupFunc) {
	t.Run("ok, lock and consume", func(t *testing.T) {
		locker, _ := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		ticket, err := locker.LockNonce(t.Context(), nonce)
		require.NoError(t, err)

		err = locker.ConsumeNonce(t.Context(), nonce, ticket)
		require.NoError(t, err)
	})

	t.Run("ok, nonce has almost expired", func(t *testing.T) {
		locker, lifespan := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		nonce.Timestamp = int64(time.Now().Add(-1*lifespan + time.Minute).Unix())
		_, err = locker.LockNonce(t.Context(), nonce)
		require.Error(t, err)
		requireInputError(t, err)
	})

	t.Run("ok, lock and release nonce multiple times", func(t *testing.T) {
		locker, _ := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		for range 5 {
			ticket, err := locker.LockNonce(t.Context(), nonce)
			require.NoError(t, err)

			err = locker.ReleaseNonce(t.Context(), nonce, ticket)
			require.NoError(t, err)
		}
	})

	t.Run("fail, nonce has expired", func(t *testing.T) {
		locker, lifespan := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		nonce.Timestamp = int64(time.Now().Add(-1*lifespan - 1*time.Second).Unix())
		_, err = locker.LockNonce(t.Context(), nonce)
		require.Error(t, err)
		requireInputError(t, err)
	})

	t.Run("fail, nonce has invalid data", func(t *testing.T) {
		locker, _ := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		nonce.Nonce = []byte{}
		_, err = locker.LockNonce(t.Context(), nonce)
		require.Error(t, err)
		requireInputError(t, err)
	})

	t.Run("fail, lock consumed nonce", func(t *testing.T) {
		locker, _ := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		ticket, err := locker.LockNonce(t.Context(), nonce)
		require.NoError(t, err)

		err = locker.ConsumeNonce(t.Context(), nonce, ticket)
		require.NoError(t, err)

		// lock again
		_, err = locker.LockNonce(t.Context(), nonce)
		require.Error(t, err)
		require.ErrorIs(t, err, anonpay.ErrNonceConsumed)
	})

	t.Run("fail, lock locked nonce", func(t *testing.T) {
		locker, _ := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		ticket, err := locker.LockNonce(t.Context(), nonce)
		require.NoError(t, err)
		defer func() {
			err = locker.ReleaseNonce(t.Context(), nonce, ticket)
			require.NoError(t, err)
		}()

		// lock again
		_, err = locker.LockNonce(t.Context(), nonce)
		require.Error(t, err)
		require.ErrorIs(t, err, anonpay.ErrNonceLocked)
	})
}

func RunConsumingTests(t *testing.T, setup fullSetupFunc) {
	t.Run("fail, never locked, no ticket", func(t *testing.T) {
		locker, _ := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		err = locker.ConsumeNonce(t.Context(), nonce, "")
		require.Error(t, err)
	})

	t.Run("fail, already consumed", func(t *testing.T) {
		locker, _ := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		ticket, err := locker.LockNonce(t.Context(), nonce)
		require.NoError(t, err)

		err = locker.ConsumeNonce(t.Context(), nonce, ticket)
		require.NoError(t, err)

		err = locker.ConsumeNonce(t.Context(), nonce, ticket)
		require.Error(t, err)
	})

	t.Run("fail, nonce has invalid data", func(t *testing.T) {
		locker, _ := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		nonce.Nonce = []byte{}
		_, err = locker.LockNonce(t.Context(), nonce)
		require.Error(t, err)
		requireInputError(t, err)
	})

	t.Run("fail, released", func(t *testing.T) {
		locker, _ := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		ticket, err := locker.LockNonce(t.Context(), nonce)
		require.NoError(t, err)

		err = locker.ReleaseNonce(t.Context(), nonce, ticket)
		require.NoError(t, err)

		err = locker.ConsumeNonce(t.Context(), nonce, ticket)
		require.Error(t, err)
	})
}

func RunReleasingTests(t *testing.T, setup fullSetupFunc) {
	t.Run("fail, never locked, no ticket", func(t *testing.T) {
		locker, _ := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		err = locker.ReleaseNonce(t.Context(), nonce, "")
		require.Error(t, err)
	})

	t.Run("fail, already released", func(t *testing.T) {
		locker, _ := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		ticket, err := locker.LockNonce(t.Context(), nonce)
		require.NoError(t, err)

		err = locker.ReleaseNonce(t.Context(), nonce, ticket)
		require.NoError(t, err)

		err = locker.ReleaseNonce(t.Context(), nonce, ticket)
		require.Error(t, err)
	})

	t.Run("fail, nonce has invalid data", func(t *testing.T) {
		locker, _ := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		nonce.Nonce = []byte{}
		_, err = locker.LockNonce(t.Context(), nonce)
		require.Error(t, err)
		requireInputError(t, err)
	})

	t.Run("fail, consumed", func(t *testing.T) {
		locker, _ := setup(t)

		nonce, err := anonpay.RandomNonce()
		require.NoError(t, err)

		ticket, err := locker.LockNonce(t.Context(), nonce)
		require.NoError(t, err)

		err = locker.ConsumeNonce(t.Context(), nonce, ticket)
		require.NoError(t, err)

		err = locker.ReleaseNonce(t.Context(), nonce, ticket)
		require.Error(t, err)
	})
}

func requireInputError(t *testing.T, err error) {
	inputErr := anonpay.InputError{}
	require.ErrorAs(t, err, &inputErr)
}
