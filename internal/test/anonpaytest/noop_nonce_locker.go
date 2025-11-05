package anonpaytest

import (
	"context"

	"github.com/openpcc/openpcc/anonpay"
)

type NoopNonceLocker struct {
}

func (l *NoopNonceLocker) CheckAndLockNonce(ctx context.Context, nonce anonpay.Nonce) (anonpay.LockedNonce, error) {
	return &noopNonceLock{}, nil
}

type noopNonceLock struct{}

func (l *noopNonceLock) Consume(ctx context.Context) error {
	return nil
}

func (l *noopNonceLock) Release(ctx context.Context) error {
	return nil
}
