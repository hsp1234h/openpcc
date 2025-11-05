package noncelocking

import (
	"context"

	"github.com/openpcc/openpcc/anonpay"
)

type TicketLockerContract interface {
	LockNonce(ctx context.Context, nonce anonpay.Nonce) (string, error)
	ConsumeNonce(ctx context.Context, nonce anonpay.Nonce, ticket string) error
	ReleaseNonce(ctx context.Context, nonce anonpay.Nonce, ticket string) error
}

type ticketLockerAdapter struct {
	locker TicketLockerContract
}

func FromTicketLocker(locker TicketLockerContract) anonpay.NonceLocker {
	return &ticketLockerAdapter{
		locker: locker,
	}
}

func (l *ticketLockerAdapter) CheckAndLockNonce(ctx context.Context, nonce anonpay.Nonce) (anonpay.LockedNonce, error) {
	ticket, err := l.locker.LockNonce(ctx, nonce)
	if err != nil {
		return nil, err
	}

	return &ticketLock{
		locker: l.locker,
		nonce:  nonce,
		ticket: ticket,
	}, nil
}

type ticketLock struct {
	locker TicketLockerContract
	nonce  anonpay.Nonce
	ticket string
}

func (l *ticketLock) Consume(ctx context.Context) error {
	return l.locker.ConsumeNonce(ctx, l.nonce, l.ticket)
}

func (l *ticketLock) Release(ctx context.Context) error {
	return l.locker.ReleaseNonce(ctx, l.nonce, l.ticket)
}
