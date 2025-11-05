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

package anonpay_test

import (
	"testing"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Exchanger(t *testing.T) {
	t.Run("ok, exchanges unblinded credit", func(t *testing.T) {
		issuer := anonpaytest.MustNewIssuer()
		payee := anonpaytest.MustNewPayee()

		nonceLocker := &testNonceLocker{}
		exchanger := anonpay.NewExchanger(issuer, nonceLocker)

		value, err := currency.Exact(31)
		require.NoError(t, err)

		unblindedCredit, err := issuer.IssueUnblindedCredit(t.Context(), value)
		require.NoError(t, err)

		unsignedCredit, err := payee.BeginBlindedCredit(t.Context(), value)
		require.NoError(t, err)

		blindSignature, err := exchanger.Exchange(t.Context(), unblindedCredit, unsignedCredit.Request())
		require.NoError(t, err)

		// verify that exchanging again fails due to the testNonceLocker.
		_, err = exchanger.Exchange(t.Context(), unblindedCredit, unsignedCredit.Request())
		require.Error(t, err)

		credit, err := unsignedCredit.Finalize(blindSignature)
		require.NoError(t, err)

		require.Equal(t, value, credit.Value())
	})

	t.Run("fail, different amounts", func(t *testing.T) {
		issuer := anonpaytest.MustNewIssuer()
		payee := anonpaytest.MustNewPayee()

		nonceLocker := &testNonceLocker{}
		exchanger := anonpay.NewExchanger(issuer, nonceLocker)

		value1, err := currency.Exact(31)
		require.NoError(t, err)
		value2, err := currency.Exact(1)
		require.NoError(t, err)

		unblindedCredit, err := issuer.IssueUnblindedCredit(t.Context(), value1)
		require.NoError(t, err)

		unsignedCredit, err := payee.BeginBlindedCredit(t.Context(), value2)
		require.NoError(t, err)

		_, err = exchanger.Exchange(t.Context(), unblindedCredit, unsignedCredit.Request())
		require.Error(t, err)
		requireInputError(t, err)
	})

	t.Run("fail, locking fails", func(t *testing.T) {
		issuer := anonpaytest.MustNewIssuer()
		payee := anonpaytest.MustNewPayee()

		nonceLocker := &testNonceLocker{
			lockErr: assert.AnError,
		}
		exchanger := anonpay.NewExchanger(issuer, nonceLocker)

		value, err := currency.Exact(31)
		require.NoError(t, err)

		unblindedCredit, err := issuer.IssueUnblindedCredit(t.Context(), value)
		require.NoError(t, err)

		unsignedCredit, err := payee.BeginBlindedCredit(t.Context(), value)
		require.NoError(t, err)

		_, err = exchanger.Exchange(t.Context(), unblindedCredit, unsignedCredit.Request())
		require.ErrorIs(t, err, assert.AnError)
	})

	t.Run("fail, release fails", func(t *testing.T) {
		issuer := anonpaytest.MustNewIssuer()
		payee := anonpaytest.MustNewPayee()

		nonceLocker := &testNonceLocker{
			unlockErr: assert.AnError,
		}
		exchanger := anonpay.NewExchanger(issuer, nonceLocker)

		value, err := currency.Exact(31)
		require.NoError(t, err)

		unblindedCredit, err := issuer.IssueUnblindedCredit(t.Context(), value)
		require.NoError(t, err)

		unsignedCredit, err := payee.BeginBlindedCredit(t.Context(), value)
		require.NoError(t, err)

		_, err = exchanger.Exchange(t.Context(), unblindedCredit, unsignedCredit.Request())
		require.Error(t, err)
	})

	t.Run("fail, consume fails", func(t *testing.T) {
		issuer := anonpaytest.MustNewIssuer()
		payee := anonpaytest.MustNewPayee()

		nonceLocker := &testNonceLocker{
			unlockErr: assert.AnError,
		}
		exchanger := anonpay.NewExchanger(issuer, nonceLocker)

		value, err := currency.Exact(31)
		require.NoError(t, err)

		unblindedCredit, err := issuer.IssueUnblindedCredit(t.Context(), value)
		require.NoError(t, err)

		unsignedCredit, err := payee.BeginBlindedCredit(t.Context(), value)
		require.NoError(t, err)

		_, err = exchanger.Exchange(t.Context(), unblindedCredit, unsignedCredit.Request())
		require.ErrorIs(t, err, assert.AnError)
	})
}

func requireInputError(t *testing.T, err error) {
	inputErr := anonpay.InputError{}
	require.ErrorAs(t, err, &inputErr)
}
