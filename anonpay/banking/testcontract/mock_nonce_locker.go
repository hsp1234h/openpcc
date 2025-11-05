package testcontract

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/stretchr/testify/require"
)

type MockNonceLocker struct {
	used []anonpay.Nonce

	expectConsumed []anonpay.Nonce
	expectReleased []anonpay.Nonce

	locked           []anonpay.Nonce
	actuallyConsumed []anonpay.Nonce
	actuallyReleased []anonpay.Nonce

	errorOnConsume []anonpay.Nonce

	t testing.TB
}

func newMockNonceLocker(t testing.TB) *MockNonceLocker {
	m := &MockNonceLocker{
		t: t,
	}
	t.Cleanup(func() {
		// Check expectations
		require.Len(t, m.locked, 0, "Some nonces were left locked")
		require.ElementsMatch(t, m.expectConsumed, m.actuallyConsumed, "Incorrect nonces were consumed")
		require.ElementsMatch(t, m.expectReleased, m.actuallyReleased, "Incorrect nonces were released")
	})
	return m
}

func (m *MockNonceLocker) MarkAlreadyUsed(nonce anonpay.Nonce) {
	m.used = append(m.used, nonce)
}

func (m *MockNonceLocker) ExpectConsumed(nonce anonpay.Nonce) {
	m.expectConsumed = append(m.expectConsumed, nonce)
}

func (m *MockNonceLocker) ExpectReleased(nonce anonpay.Nonce) {
	m.expectReleased = append(m.expectReleased, nonce)
}

func (m *MockNonceLocker) ReturnErrorWhenConsumeCalledFor(nonce anonpay.Nonce) {
	m.errorOnConsume = append(m.errorOnConsume, nonce)
}

type mockLock struct {
	m      *MockNonceLocker
	nonce  anonpay.Nonce
	locked bool
}

func (m *MockNonceLocker) CheckAndLockNonce(ctx context.Context, nonce anonpay.Nonce) (anonpay.LockedNonce, error) {
	for i := range m.used {
		if reflect.DeepEqual(m.used[i], nonce) {
			return nil, errors.New("nonce already consumed")
		}
	}

	found := false
	for i := range m.expectConsumed {
		if reflect.DeepEqual(m.expectConsumed[i], nonce) {
			found = true
			break
		}
	}
	for i := range m.expectReleased {
		if reflect.DeepEqual(m.expectReleased[i], nonce) {
			found = true
			break
		}
	}
	if !found {
		m.t.Error("CheckAndLockNonce called on unexpected nonce", nonce)
	}

	m.locked = append(m.locked, nonce)

	return &mockLock{
		m:      m,
		nonce:  nonce,
		locked: true,
	}, nil
}

func (lock *mockLock) Consume(ctx context.Context) error {
	if !lock.locked {
		lock.m.t.Error("tried to consume unlocked nonce")
		return errors.New("nonce unlocked")
	}

	for i := range lock.m.errorOnConsume {
		if reflect.DeepEqual(lock.m.errorOnConsume[i], lock.nonce) {
			return errors.New("failed to consume nonce")
		}
	}

	lock.m.locked = without(lock.m.locked, lock.nonce)
	lock.m.actuallyConsumed = append(lock.m.actuallyConsumed, lock.nonce)

	lock.locked = false

	return nil
}

func (lock *mockLock) Release(ctx context.Context) error {
	if !lock.locked {
		// Meet contract that we can safely call Release after Consume
		return nil
	}
	lock.m.locked = without(lock.m.locked, lock.nonce)
	lock.m.actuallyReleased = append(lock.m.actuallyReleased, lock.nonce)

	lock.locked = false

	return nil
}
