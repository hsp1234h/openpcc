package anonpay

import (
	"errors"
	"fmt"

	"github.com/openpcc/openpcc/anonpay/currency"
)

var (
	// ErrNonceConsumed indicates a nonce has been consumed and can't be locked.
	//
	// Must be returned by the [NonceLocker] when the caller attempts to lock a consumed nonce.
	ErrNonceConsumed = errors.New("nonce is consumed")

	// ErrNonceLocked indicates a nonce is currently locked and can't be locked again.
	//
	// Must be returned by the [NonceLocker] when the caller attempts to lock a locked nonce.
	ErrNonceLocked = errors.New("nonce is locked")
)

// InsufficientBalanceError indicates an operation failed due to
// their not being enough balance available.
type InsufficientBalanceError struct {
	// Balance indicates the balance at the time of the error. It may
	// be set to -1 to indicate the balance wasn't known.
	Balance int64
}

func (e InsufficientBalanceError) KnownBalance() bool {
	return e.Balance >= 0
}

func (e InsufficientBalanceError) Error() string {
	if e.KnownBalance() {
		return "insufficient balance"
	}
	return fmt.Sprintf("insufficient balance %d", e.Balance)
}

// CreditsNotAvailableError indicates an operation failed, due to the requested credits
// not being available.
type CreditsNotAvailableError struct {
	// Credits is the number of requested credits.
	Credits int
	// Amount is the amount of currency that each credit should have been worth.
	Amount currency.Value
}

func (e CreditsNotAvailableError) Error() string {
	return fmt.Sprintf(
		"credits not available %dx%d (%d)", e.Credits, e.Amount.AmountOrZero(), int64(e.Credits)*e.Amount.AmountOrZero(),
	)
}

// VerififcationFailed indicates the verification of a credit failed.
type VerificationError struct {
	Err error
}

func (e VerificationError) Error() string {
	return e.Err.Error()
}

func (e VerificationError) Unwrap() error {
	return e.Err
}

// InputError indicates the provided input was invalid.
type InputError struct {
	Err error
}

func (e InputError) Error() string {
	return e.Err.Error()
}

func (e InputError) Unwrap() error {
	return e.Err
}
