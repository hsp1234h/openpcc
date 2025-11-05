package testcontract

import (
	"reflect"
	"slices"
	"testing"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/banking"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
	"github.com/stretchr/testify/require"
)

type SetupFunc func(t *testing.T, nonceLocker anonpay.NonceLocker) (banking.BlindBankContract, error)

func TestBlindBankContract(t *testing.T, setupFunc SetupFunc) {
	setup := func(t *testing.T) (*MockNonceLocker, banking.BlindBankContract) {
		t.Helper()

		nonceHandler := newMockNonceLocker(t)

		bank, err := setupFunc(t, nonceHandler)
		require.NoError(t, err)

		return nonceHandler, bank
	}

	t.Run("Deposit", func(t *testing.T) {
		runDepositTests(t, setup)
	})

	t.Run("WithdrawBatch", func(t *testing.T) {
		runWithdrawBatchTests(t, setup)
	})

	t.Run("WithdrawFullUnblinded", func(t *testing.T) {
		runWithdrawFullUnblindedTests(t, setup)
	})

	t.Run("Exchange", func(t *testing.T) {
		runExchangeTests(t, setup)
	})

	t.Run("Balance", func(t *testing.T) {
		runBalanceTests(t, setup)
	})
}

type fullSetupFunc func(t *testing.T) (*MockNonceLocker, banking.BlindBankContract)

func runDepositTests(t *testing.T, setup fullSetupFunc) {
	t.Run("ok", func(t *testing.T) {
		account := newAccount(t)
		nonceHandler, bank := setup(t)

		// deposit a few credits and verify the balance can go beyond the max currency amount.
		wantBalance := int64(0)
		for _, amount := range []int64{1, 2, 3, 4, currency.MaxAmount} {
			credit := newExactCredit(t, amount)
			nonceHandler.ExpectConsumed(credit.Nonce())

			balance, err := bank.Deposit(t.Context(), []byte{}, account, credit)
			require.NoError(t, err)

			wantBalance += amount
			require.Equal(t, wantBalance, balance)
			requireAccountBalance(t, bank, account, wantBalance)
		}
	})

	t.Run("fail, amount needs to be 1 or greater", func(t *testing.T) {
		account := newAccount(t)
		credit := newExactCredit(t, 0)

		_, bank := setup(t)

		_, err := bank.Deposit(t.Context(), []byte{}, account, credit)
		require.Error(t, err)

		requireAccountBalance(t, bank, account, 0)
	})

	t.Run("fail, transaction commit fails", func(t *testing.T) {
		account := newAccount(t)
		credit := newExactCredit(t, 1)

		nonceHandler, bank := setup(t)
		nonceHandler.ReturnErrorWhenConsumeCalledFor(credit.Nonce())
		nonceHandler.ExpectReleased(credit.Nonce()) // Since consume will error, we expect a release attempt

		_, err := bank.Deposit(t.Context(), []byte{}, account, credit)
		require.Error(t, err)

		requireAccountBalance(t, bank, account, 0)
	})

	t.Run("fail, verification fails", func(t *testing.T) {
		account := newAccount(t)
		credit := newTamperedCredit(t, 10)

		_, bank := setup(t)

		_, err := bank.Deposit(t.Context(), []byte{}, account, credit)
		require.Error(t, err)
		requireInputError(t, err)

		requireAccountBalance(t, bank, account, 0)
	})

	t.Run("fail, special credit", func(t *testing.T) {
		account := newAccount(t)
		credit := newSpecialCredit(t)

		_, bank := setup(t)

		_, err := bank.Deposit(t.Context(), []byte{}, account, credit)
		require.Error(t, err)
		requireInputError(t, err)

		requireAccountBalance(t, bank, account, 0)
	})
}

func runWithdrawFullUnblindedTests(t *testing.T, setup fullSetupFunc) {
	t.Run("ok, withdraw max", func(t *testing.T) {
		payee := anonpaytest.MustNewPayee()
		nonceHandler, bank := setup(t)

		for _, balance := range []int64{1, 2, 1024, currency.MaxAmount} {
			account, _ := newAccountWithBalance(t, nonceHandler, bank, balance)

			credit, err := bank.WithdrawFullUnblinded(t.Context(), []byte{}, account)
			require.NoError(t, err)

			err = payee.VerifyCredit(t.Context(), credit)
			require.NoError(t, err)

			require.Equal(t, credit.Value().AmountOrZero(), balance)
			requireAccountBalance(t, bank, account, 0)
		}
	})

	t.Run("ok, withdraw unrepresentable balance", func(t *testing.T) {
		payee := anonpaytest.MustNewPayee()
		nonceHandler, bank := setup(t)

		require.False(t, currency.CanRepresent(1025))
		account, _ := newAccountWithBalance(t, nonceHandler, bank, 1024, 1)

		credit, err := bank.WithdrawFullUnblinded(t.Context(), []byte{}, account)
		require.NoError(t, err)

		err = payee.VerifyCredit(t.Context(), credit)
		require.NoError(t, err)

		minVal, err := currency.Rounded(1025, 0.0)
		require.NoError(t, err)

		maxVal, err := currency.Rounded(1025, 1.0)
		require.NoError(t, err)

		require.GreaterOrEqual(t, credit.Value().AmountOrZero(), minVal.AmountOrZero())
		require.LessOrEqual(t, credit.Value().AmountOrZero(), maxVal.AmountOrZero())

		requireAccountBalance(t, bank, account, 0)
	})

	t.Run("fail, non-existent account and zero account", func(t *testing.T) {
		nonceHandler, bank := setup(t)

		existingAccount, _ := newAccountWithBalance(t, nonceHandler, bank, 1)
		// withdraw the credits from the account.
		_, err := bank.WithdrawFullUnblinded(t.Context(), []byte{}, existingAccount)
		require.NoError(t, err)

		// do it again, but now on the zero-balance account.
		_, zeroBalanceErr := bank.WithdrawFullUnblinded(t.Context(), []byte{}, existingAccount)
		require.Error(t, zeroBalanceErr)

		// withdraw from an account that never saw any deposits.
		nonExistingAccount := newAccount(t)
		_, nonExistingErr := bank.WithdrawFullUnblinded(t.Context(), []byte{}, nonExistingAccount)
		require.Error(t, nonExistingErr)

		// check that the errors have equivalent messages.
		require.Equal(t, zeroBalanceErr.Error(), nonExistingErr.Error())

		requireAccountBalance(t, bank, existingAccount, 0)
	})

	t.Run("fail, balance over max currency", func(t *testing.T) {
		nonceHandler, bank := setup(t)

		account, _ := newAccountWithBalance(t, nonceHandler, bank, currency.MaxAmount, 1)

		_, err := bank.WithdrawFullUnblinded(t.Context(), []byte{}, account)
		require.Error(t, err)

		requireAccountBalance(t, bank, account, currency.MaxAmount+1)
	})
}

func runWithdrawBatchTests(t *testing.T, setup fullSetupFunc) {
	prepCredits := func(t *testing.T, amounts ...int64) ([]anonpay.BlindSignState, []anonpay.BlindSignRequest) {
		t.Helper()

		payee := anonpaytest.MustNewPayee()

		state := make([]anonpay.BlindSignState, 0, len(amounts))
		reqs := make([]anonpay.BlindSignRequest, 0, len(amounts))
		for _, amount := range amounts {
			val, err := currency.Exact(amount)
			require.NoError(t, err)

			s, err := payee.BeginBlindedCredit(t.Context(), val)
			require.NoError(t, err)

			state = append(state, *s)
			reqs = append(reqs, s.Request())
		}

		return state, reqs
	}

	validateResults := func(t *testing.T, batch []int64, state []anonpay.BlindSignState, blindSignatures [][]byte) {
		t.Helper()

		require.Equal(t, len(batch), len(blindSignatures))

		payee := anonpaytest.MustNewPayee()
		for i, amount := range batch {
			credit, err := state[i].Finalize(blindSignatures[i])
			require.NoError(t, err)

			err = payee.VerifyCredit(t.Context(), credit)
			require.NoError(t, err)

			require.Equal(t, amount, credit.Value().AmountOrZero())
		}
	}

	tests := map[string]struct {
		deposits     []int64
		batch        []int64
		wantBalance  int64
		wantErr      bool
		wantInputErr bool
	}{
		"ok, single credit in batch": {
			deposits:    []int64{1},
			batch:       []int64{1},
			wantBalance: 0,
		},
		"ok, multiple credits in batch": {
			deposits:    []int64{3},
			batch:       []int64{1, 1, 1},
			wantBalance: 0,
		},
		"ok, max credits in batch": {
			deposits:    []int64{15},
			batch:       slices.Repeat([]int64{1}, 15),
			wantBalance: 0,
		},
		"ok, max credits in batch of max currency": {
			deposits:    slices.Repeat([]int64{currency.MaxAmount}, 15),
			batch:       slices.Repeat([]int64{currency.MaxAmount}, 15),
			wantBalance: 0,
		},
		"fail, single credit, 0 balance": {
			deposits:    []int64{},
			batch:       []int64{1},
			wantBalance: 0,
			wantErr:     true,
		},
		"fail, multiple credits, 0 balance": {
			deposits:    []int64{},
			batch:       []int64{1, 1, 1},
			wantBalance: 0,
			wantErr:     true,
		},
		"fail, single credit, insufficient balance": {
			deposits:    []int64{2},
			batch:       []int64{3},
			wantBalance: 2,
			wantErr:     true,
		},
		"fail, multiple credits, insufficient balance": {
			deposits:    []int64{8},
			batch:       []int64{3, 3, 3},
			wantBalance: 8,
			wantErr:     true,
		},
		"fail, empty batch": {
			deposits:     []int64{1},
			batch:        []int64{},
			wantBalance:  1,
			wantErr:      true,
			wantInputErr: true,
		},
		"fail, too many credits in batch": {
			deposits:     []int64{16},
			batch:        slices.Repeat([]int64{1}, 16),
			wantBalance:  16,
			wantErr:      true,
			wantInputErr: true,
		},
		"fail, zero credit in batch": {
			deposits:     []int64{8},
			batch:        []int64{3, 0, 3},
			wantBalance:  8,
			wantErr:      true,
			wantInputErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			nonceHandler, bank := setup(t)
			account, _ := newAccountWithBalance(t, nonceHandler, bank, tc.deposits...)

			states, reqs := prepCredits(t, tc.batch...)

			gotBalance, blindSignatures, err := bank.WithdrawBatch(t.Context(), []byte{}, account, reqs)
			if tc.wantErr {
				require.Error(t, err)
				requireAccountBalance(t, bank, account, tc.wantBalance)

				if tc.wantInputErr {
					requireInputError(t, err)
				}
				return
			}

			require.NoError(t, err)

			validateResults(t, tc.batch, states, blindSignatures)

			require.Equal(t, tc.wantBalance, gotBalance)
			requireAccountBalance(t, bank, account, tc.wantBalance)
		})
	}

	t.Run("fail, special credit", func(t *testing.T) {
		nonceHandler, bank := setup(t)
		account, _ := newAccountWithBalance(t, nonceHandler, bank, 10)

		_, reqs := prepCredits(t, 1, 3, 1)
		payee := anonpaytest.MustNewPayee()
		state, err := payee.BeginBlindedCredit(t.Context(), currency.MustSpecial(1))
		require.NoError(t, err)

		reqs[1] = state.Request()

		_, _, err = bank.WithdrawBatch(t.Context(), []byte{}, account, reqs)
		require.Error(t, err)
		requireInputError(t, err)
	})

	t.Run("fail, non-existent account and zero account", func(t *testing.T) {
		nonceHandler, bank := setup(t)

		existingAccount, _ := newAccountWithBalance(t, nonceHandler, bank, 1)
		// withdraw the credits from the account.
		_, reqs := prepCredits(t, 1)
		_, _, err := bank.WithdrawBatch(t.Context(), []byte{}, existingAccount, reqs)
		require.NoError(t, err)

		// do it again, but now on the zero-balance account.
		_, reqs = prepCredits(t, 1)
		_, _, zeroBalanceErr := bank.WithdrawBatch(t.Context(), []byte{}, existingAccount, reqs)
		require.Error(t, zeroBalanceErr)

		// withdraw from an account that never saw any deposits.
		nonExistingAccount := newAccount(t)
		_, reqs = prepCredits(t, 1)
		_, _, nonExistingErr := bank.WithdrawBatch(t.Context(), []byte{}, nonExistingAccount, reqs)
		require.Error(t, nonExistingErr)

		// check that the errors have equivalent messages.
		require.Equal(t, zeroBalanceErr.Error(), nonExistingErr.Error())

		requireAccountBalance(t, bank, existingAccount, 0)
	})

	t.Run("fail, duplicate request", func(t *testing.T) {
		nonceHandler, bank := setup(t)
		account, _ := newAccountWithBalance(t, nonceHandler, bank, 10)

		_, reqs := prepCredits(t, 5)
		reqs = append(reqs, reqs[0])

		_, _, err := bank.WithdrawBatch(t.Context(), []byte{}, account, reqs)
		require.Error(t, err)
		requireInputError(t, err)
	})
}

func runExchangeTests(t *testing.T, setup fullSetupFunc) {
	t.Run("ok", func(t *testing.T) {
		payee := anonpaytest.MustNewPayee()
		nonceHandler, bank := setup(t)

		for _, amount := range []int64{currency.MaxAmount, 1024, 1} {
			credit := newExactCredit(t, amount)
			val, err := currency.Exact(amount)
			require.NoError(t, err)
			nonceHandler.ExpectConsumed(credit.Nonce())

			state, err := payee.BeginBlindedCredit(t.Context(), val)
			require.NoError(t, err)

			blindSignature, err := bank.Exchange(t.Context(), []byte{}, credit, state.Request())
			require.NoError(t, err)

			gotCredit, err := state.Finalize(blindSignature)
			require.NoError(t, err)

			require.Equal(t, gotCredit.Value(), credit.Value())
		}
	})

	t.Run("fail, can't exchange credit with 0 amount", func(t *testing.T) {
		payee := anonpaytest.MustNewPayee()
		_, bank := setup(t)

		credit := newExactCredit(t, 0)
		val, err := currency.Exact(0)
		require.NoError(t, err)

		state, err := payee.BeginBlindedCredit(t.Context(), val)
		require.NoError(t, err)

		_, err = bank.Exchange(t.Context(), []byte{}, credit, state.Request())
		require.Error(t, err)
		requireInputError(t, err)
	})

	t.Run("fail, can't exchange special credit", func(t *testing.T) {
		payee := anonpaytest.MustNewPayee()
		_, bank := setup(t)

		credit := newSpecialCredit(t)
		state, err := payee.BeginBlindedCredit(t.Context(), credit.Value())
		require.NoError(t, err)

		_, err = bank.Exchange(t.Context(), []byte{}, credit, state.Request())
		require.Error(t, err)
		requireInputError(t, err)
	})

	t.Run("fail, exchanger error", func(t *testing.T) {
		payee := anonpaytest.MustNewPayee()
		_, bank := setup(t)

		credit := newTamperedCredit(t, 1)
		state, err := payee.BeginBlindedCredit(t.Context(), credit.Value())
		require.NoError(t, err)

		_, err = bank.Exchange(t.Context(), []byte{}, credit, state.Request())
		require.Error(t, err)
		requireInputError(t, err)
	})
}

func runBalanceTests(t *testing.T, setup fullSetupFunc) {
	t.Run("ok, non-existent account and zero account both return zero", func(t *testing.T) {
		nonceHandler, bank := setup(t)

		existingAccount, _ := newAccountWithBalance(t, nonceHandler, bank, 1)
		// withdraw the credits from the account.
		_, err := bank.WithdrawFullUnblinded(t.Context(), []byte{}, existingAccount)
		require.NoError(t, err)

		// verify the balance is zero for the existing account.
		balance, err := bank.Balance(t.Context(), existingAccount)
		require.NoError(t, err)
		require.Equal(t, int64(0), balance)

		// verify the balance is zero for the nonexisting account.
		nonExistingAccount := newAccount(t)
		balance, err = bank.Balance(t.Context(), nonExistingAccount)
		require.NoError(t, err)
		require.Equal(t, int64(0), balance)
	})
}

func without(nonces []anonpay.Nonce, nonce anonpay.Nonce) []anonpay.Nonce {
	var result []anonpay.Nonce
	for i := range nonces {
		if !reflect.DeepEqual(nonces[i], nonce) {
			result = append(result, nonces[i])
		}
	}
	return result
}

func newExactCredit(t *testing.T, amount int64) *anonpay.BlindedCredit {
	value, err := currency.Exact(amount)
	require.NoError(t, err)

	return anonpaytest.MustBlindCredit(t.Context(), value)
}

func newSpecialCredit(t *testing.T) *anonpay.BlindedCredit {
	value := currency.MustSpecial(1)
	return anonpaytest.MustBlindCredit(t.Context(), value)
}

// tampered credits will fail verification.
func newTamperedCredit(t *testing.T, amount int64) *anonpay.BlindedCredit {
	credit := newExactCredit(t, amount)
	pb, err := credit.MarshalProto()
	require.NoError(t, err)
	pb.GetSignature()[0]++
	err = credit.UnmarshalProto(pb)
	require.NoError(t, err)
	return credit
}

func newAccount(t *testing.T) banking.AccountToken {
	account, err := banking.GenerateAccountToken()
	require.NoError(t, err)
	return account
}

func newAccountWithBalance(t *testing.T, nonceHandler *MockNonceLocker, bank banking.BlindBankContract, amounts ...int64) (banking.AccountToken, int64) {
	account := newAccount(t)
	balance := int64(0)
	for _, amount := range amounts {
		credit := newExactCredit(t, amount)
		nonceHandler.ExpectConsumed(credit.Nonce())

		_, err := bank.Deposit(t.Context(), []byte{}, account, credit)
		require.NoError(t, err)
		balance += amount
	}

	return account, balance
}

func requireAccountBalance(t *testing.T, bank banking.BlindBankContract, account banking.AccountToken, expectedBalance int64) {
	t.Helper()
	balance, err := bank.Balance(t.Context(), account)
	require.NoError(t, err)

	require.Equal(t, expectedBalance, balance)
}

func requireInputError(t *testing.T, err error) {
	inputErr := anonpay.InputError{}
	require.ErrorAs(t, err, &inputErr)
}
