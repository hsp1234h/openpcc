package banking

import (
	"context"

	"github.com/openpcc/openpcc/anonpay"
)

// MaxBatchLen is the maximum batch length allowed for blind bank operations.
const MaxBatchLen = 15

// Contract is the contract a blind bank needs to fullfil to be compatible with the anonpay ecosystem.
//
// Implementors can verify their implementations works by running the tests in the testcontract package.
//
// Note: The transferID's are there to support a yet-to-be-implemented crash-recovery feature where the transferID's
// will be used as idempotency ID's.
type BlindBankContract interface {
	// WithdrawBatch withdraws a batch of credits from a single account.
	// This first return value is the updated balance, and the second return value
	//
	// - Must return an [anonpay.InputError] error when 0 requests are provided.
	// - Must support up to [MaxBatchLen] credits per operation.
	// - Must return an [anonpay.InputError] when more than [MaxBatchLen] blind signing requests are provided.
	// - Must return signatures that result in credits that can be finalized and verified.
	// - Must return an [anonpay.InputError] when a request has a currency value with a zero amount.
	// - Must return an [anonpay.InputError] when a request has a currency value with a zero amount.
	// - Must return the an when this account has no balance or has never credits deposited into it. The error must be the same for both cases to prevent account enumeration.
	// - Must fail or complete all requests. No partially succesful withdrawals.
	// - Must return the updated balance of the account.
	// - Must return blind signatures in the same order as the requests.
	WithdrawBatch(ctx context.Context, transferID []byte, account AccountToken, reqs []anonpay.BlindSignRequest) (balance int64, blindSignatures [][]byte, err error)

	// WithdrawFullUnblinded withdraws the full balance of an account. It should return an unblinded credit that can be exchanged.
	//
	// - Must return an error when this account has no balance or has never credits deposited into it. The error must be the same for both cases to prevent account enumeration.
	// - Must stochastically round the balance if it can't be represented as a currency value.
	// - Must return an error if the account balance is greater than the maximum value that can be represented.
	WithdrawFullUnblinded(ctx context.Context, transferID []byte, account AccountToken) (*anonpay.UnblindedCredit, error)

	// Deposit deposit a single credits into a single bank account. If the account does not exist, a new account should be created.
	//
	// - Must return an [anonpay.InputError] when credit can't be verified.
	// - Must error when the credit has a currency value with a zero amount.
	// - Must error when the credit has a special currency value.
	// - Must fail or complete all deposited credits. No partially succesful deposit operations.
	// - Must return the updated balance of the account.
	Deposit(ctx context.Context, transferID []byte, account AccountToken, credit *anonpay.BlindedCredit) (balance int64, err error)

	// Exchange exchanges a single credit for a new credit.
	//
	// - Must return an [anonpay.InputError] when credit can't be verified.
	// - Must support unblinded and blinded credits.
	// - Must return a blinded signature that result in credits that can be finalized and verified.
	// - Must error when the input credit has a currency value with a zero amount.
	// - Must error when the input credit has a special currency value.
	Exchange(ctx context.Context, transferID []byte, credit anonpay.AnyCredit, request anonpay.BlindSignRequest) (blindSignature []byte, err error)

	// Balance returns the balance of an account.
	//
	// - Must return a zero balance for non exisiting accounts.
	Balance(ctx context.Context, account AccountToken) (balance int64, err error)
}
