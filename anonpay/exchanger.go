package anonpay

import (
	"context"
	"errors"
	"fmt"

	"github.com/openpcc/openpcc/otel/otelutil"
)

// Exchanger exchanges an unblinded credit for a credit.
type Exchanger struct {
	issuer      *Issuer
	nonceLocker NonceLocker
}

func NewExchanger(issuer *Issuer, nonceLocker NonceLocker) *Exchanger {
	return &Exchanger{
		issuer:      issuer,
		nonceLocker: nonceLocker,
	}
}

func (e *Exchanger) Exchange(ctx context.Context, credit AnyCredit, req BlindSignRequest) ([]byte, error) {
	_, span := otelutil.Tracer.Start(ctx, "anonpay.Exchanger.Exchanger")
	defer span.End()

	if credit.Value() != req.Value {
		return nil, InputError{
			Err: fmt.Errorf("non-matching value: %v and %v", credit.Value(), req.Value),
		}
	}

	// Verify the credit
	err := e.issuer.VerifyCredit(ctx, credit)
	if err != nil {
		return nil, InputError{
			Err: fmt.Errorf("failed to validate credit signature: %w", err),
		}
	}

	// Lock nonce
	nonceLock, err := e.nonceLocker.CheckAndLockNonce(ctx, credit.Nonce())
	if err != nil {
		return nil, fmt.Errorf("failed to lock credit nonce: %w", err)
	}

	// Build signature for exchanged credit
	signature, err := e.issuer.BlindSign(ctx, req)
	if err != nil {
		err = errors.Join(err, nonceLock.Release(ctx))
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// Consume the original credit
	if err := nonceLock.Consume(ctx); err != nil {
		return nil, fmt.Errorf("failed to consume nonce: %w", err)
	}

	return signature, err
}
