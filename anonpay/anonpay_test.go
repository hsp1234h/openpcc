package anonpay_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/gen/protos"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test_BlindedFlow(t *testing.T) {
	payee := anonpaytest.MustNewPayee()
	issuer := anonpaytest.MustNewIssuer()

	value, err := currency.Exact(17)
	require.NoError(t, err)

	unsignedCredit, err := payee.BeginBlindedCredit(t.Context(), value)
	require.NoError(t, err)
	require.Equal(t, value, unsignedCredit.Value())

	blindSig, err := issuer.BlindSign(t.Context(), unsignedCredit.Request())
	require.NoError(t, err)

	credit, err := unsignedCredit.Finalize(blindSig)
	require.NoError(t, err)

	require.Equal(t, value, credit.Value())

	err = issuer.VerifyCredit(t.Context(), credit)
	require.NoError(t, err)

	err = payee.VerifyCredit(t.Context(), credit)
	require.NoError(t, err)
}

func Test_UnblindedFlow(t *testing.T) {
	payee := anonpaytest.MustNewPayee()
	issuer := anonpaytest.MustNewIssuer()

	value, err := currency.Exact(31)
	require.NoError(t, err)

	unblindedCredit, err := issuer.IssueUnblindedCredit(t.Context(), value)
	require.NoError(t, err)

	require.Equal(t, value, unblindedCredit.Value())

	err = payee.VerifyCredit(t.Context(), unblindedCredit)
	require.NoError(t, err)

	err = issuer.VerifyCredit(t.Context(), unblindedCredit)
	require.NoError(t, err)
}

func Test_MixingUpBlindCreditFailsToFinalize(t *testing.T) {
	issuer := anonpaytest.MustNewIssuer()
	payee := anonpaytest.MustNewPayee()

	value, err := currency.Exact(17)
	require.NoError(t, err)

	unsignedCredit, err := payee.BeginBlindedCredit(t.Context(), value)
	require.NoError(t, err)

	otherUnsignedCredit, err := payee.BeginBlindedCredit(t.Context(), value)
	require.NoError(t, err)

	blindedSignature, err := issuer.BlindSign(t.Context(), unsignedCredit.Request())
	require.NoError(t, err)

	_, err = otherUnsignedCredit.Finalize(blindedSignature)
	require.Error(t, err)
}

func Test_Manipulation_Fails(t *testing.T) {
	tests := map[string]func(c *protos.Credit) error{
		"amount": func(c *protos.Credit) error {
			val, err := currency.Exact(currency.MaxAmount)
			if err != nil {
				return err
			}
			valPB, err := val.MarshalProto()
			if err != nil {
				return err
			}

			c.SetValue(valPB)
			return nil
		},
		"nonce value": func(c *protos.Credit) error {
			c.GetNonce().GetNonce()[0]++
			return nil
		},
		"nonce timestamp": func(c *protos.Credit) error {
			nowPlusHour := time.Now().Add(time.Hour)
			c.GetNonce().SetTimestamp(timestamppb.New(nowPlusHour))
			return nil
		},
		"signature": func(c *protos.Credit) error {
			c.GetSignature()[0]++
			return nil
		},
	}
	for name, modFunc := range tests {
		t.Run("blinded, manipulate "+name, func(t *testing.T) {
			issuer := anonpaytest.MustNewIssuer()
			payee := anonpaytest.MustNewPayee()

			value, err := currency.Exact(17)
			require.NoError(t, err)

			credit := anonpaytest.MustBlindCredit(t.Context(), value)

			creditPB, err := credit.MarshalProto()
			require.NoError(t, err)

			require.NoError(t, modFunc(creditPB))

			err = credit.UnmarshalProto(creditPB)
			require.NoError(t, err)

			err = issuer.VerifyCredit(t.Context(), credit)
			require.Error(t, err)

			err = payee.VerifyCredit(t.Context(), credit)
			require.Error(t, err)
		})

		t.Run("unblinded, manipulate "+name, func(t *testing.T) {
			issuer := anonpaytest.MustNewIssuer()
			payee := anonpaytest.MustNewPayee()

			value, err := currency.Exact(17)
			require.NoError(t, err)

			credit := anonpaytest.MustUnblindCredit(t.Context(), value)

			creditPB, err := credit.MarshalProto()
			require.NoError(t, err)

			require.NoError(t, modFunc(creditPB))

			err = credit.UnmarshalProto(creditPB)
			require.NoError(t, err)

			err = issuer.VerifyCredit(t.Context(), credit)
			require.Error(t, err)

			err = payee.VerifyCredit(t.Context(), credit)
			require.Error(t, err)
		})
	}
}

type testNonceLocker struct {
	consumed  []anonpay.Nonce
	lockErr   error
	unlockErr error
}

func (l *testNonceLocker) CheckAndLockNonce(ctx context.Context, nonce anonpay.Nonce) (anonpay.LockedNonce, error) {
	for _, seen := range l.consumed {
		if bytes.Equal(seen.Nonce, nonce.Nonce) {
			return nil, errors.New("nonce consumed")
		}
	}

	return &testLock{
		locker: l,
		nonce:  nonce,
	}, l.lockErr
}

type testLock struct {
	locker *testNonceLocker
	nonce  anonpay.Nonce
}

func (l *testLock) Consume(ctx context.Context) error {
	l.locker.consumed = append(l.locker.consumed, l.nonce)
	return l.locker.unlockErr
}

func (l *testLock) Release(ctx context.Context) error {
	return l.locker.unlockErr
}
