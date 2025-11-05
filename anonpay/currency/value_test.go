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

package currency_test

import (
	"bytes"
	"math"
	"math/rand"
	"strconv"
	"testing"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/gen/protos"
	"github.com/stretchr/testify/require"
)

func TestExactErrors(t *testing.T) {
	_, err := currency.Exact(-1)
	require.ErrorIs(t, err, currency.ErrNegativeUnrepresentable)

	_, err = currency.Exact(100_000_000_000)
	require.ErrorIs(t, err, currency.ErrOverflow)

	_, err = currency.Exact(507_903)
	require.ErrorIs(t, err, currency.ErrNoExactRepresentation)

	_, err = currency.Exact(0b11_1111)
	require.ErrorIs(t, err, currency.ErrNoExactRepresentation)

	_, err = currency.Exact(0b1111_1100)
	require.ErrorIs(t, err, currency.ErrNoExactRepresentation)
}

func TestExactWorksOnAllValues(t *testing.T) {
	for i := int64(0); i < 16; i++ {
		c, err := currency.Exact(i)
		require.NoError(t, err)
		amount, err := c.Amount()
		require.NoError(t, err)
		require.Equal(t, i, amount)
	}
	for e := 0; e < 15; e++ {
		for i := 16; i < 32; i++ {
			expected := int64(i << e)
			c, err := currency.Exact(expected)
			require.NoError(t, err)
			amount, err := c.Amount()
			require.NoError(t, err)
			require.Equal(t, expected, amount)
		}
	}
}

func TestCurrencyBlindBytesRoundtrip(t *testing.T) {
	var buffer = make([]byte, 2)
	for i := 0; i < 512; i++ {
		buffer[0] = 0
		if i >= 256 {
			buffer[0] = 2
		}
		buffer[1] = byte(i)
		c, err := currency.ParseCurrencyFromBlindBytes(buffer)
		require.NoError(t, err)

		n, err := c.Amount()
		require.NoError(t, err)

		println("Amount: " + strconv.FormatInt(n, 10))

		d, err := currency.Exact(n)
		require.NoError(t, err)

		dBytes, err := d.BlindBytes()
		require.NoError(t, err)

		require.Equal(t, buffer, dBytes)
	}
}

func TestCurrencyBlindBytesErrors(t *testing.T) {
	_, err := currency.ParseCurrencyFromBlindBytes(nil)
	require.ErrorIs(t, err, currency.ErrTooShort)

	_, err = currency.ParseCurrencyFromBlindBytes([]byte{4, 0})
	require.ErrorIs(t, err, currency.ErrTooManyBitsSet)
}

func TestRounded(t *testing.T) {
	relativeError := 0.0
	const N = 1000
	source := rand.NewSource(42)
	r := rand.New(source)
	for i := 0; i < N; i++ {
		var amount float64
		for {
			// Sample a reasonable distribution of amounts
			amount = r.ExpFloat64() * currency.MaxAmount / 10
			if amount < currency.MaxAmount {
				break
			}
		}
		factor := r.Float64()
		c, err := currency.Rounded(float64(amount), factor)

		require.NoError(t, err)

		roundedAmount, err := c.Amount()

		require.NoError(t, err)

		errorAmount := (float64(roundedAmount) - amount) / float64(amount)

		// Make sure no output has a relative error more than 6.25% (the maximum)
		require.LessOrEqual(t, math.Abs(errorAmount), 0.0625)

		relativeError += errorAmount
	}
	require.LessOrEqual(t, math.Abs(relativeError)/N, 0.001) // Less than 0.1% average relative error
}

func TestRoundedFractionalValues(t *testing.T) {
	c, err := currency.Rounded(1.6, 0)
	require.NoError(t, err)
	amount, err := c.Amount()
	require.NoError(t, err)
	require.Equal(t, int64(1), amount)

	c, err = currency.Rounded(1.6, 1)
	require.NoError(t, err)
	amount, err = c.Amount()
	require.NoError(t, err)
	require.Equal(t, int64(2), amount)

	c, err = currency.Rounded(1.6, 0.5)
	require.NoError(t, err)
	amount, err = c.Amount()
	require.NoError(t, err)
	require.Equal(t, int64(2), amount)
}

func TestRoundedIntegers(t *testing.T) {
	for i := 1; i < 1024; i++ {
		c, err := currency.Rounded(float64(i), 0)
		require.NoError(t, err)
		amount, err := c.Amount()
		require.NoError(t, err)
		require.InDelta(t, i, amount, float64(i)*0.0625)
	}
}

func TestExactLargeAmountWithFractionalPartIsRoundedUpCorrectly(t *testing.T) {
	c, err := currency.Rounded(64.1, 1) // Round up, which takes us to 68
	require.NoError(t, err)
	amount, err := c.Amount()
	require.NoError(t, err)
	require.Equal(t, int64(68), amount)
}

func TestCurrencyMarshalUnmarshalProto(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pbc := &protos.Currency{}
		pbc.SetCurrency([]byte{0, 10})

		want, err := currency.Exact(10)
		require.NoError(t, err)

		got := currency.Value{}
		err = got.UnmarshalProto(pbc)
		require.NoError(t, err)
		require.Equal(t, want, got)

		// check again but with non-hardcoded pb
		pbc, err = got.MarshalProto()
		require.NoError(t, err)

		err = got.UnmarshalProto(pbc)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	failTests := map[string]func(*protos.Currency){
		"fail, missing currency": func(pbn *protos.Currency) {
			pbn.ClearCurrency()
		},
		"fail, nil currency": func(pbn *protos.Currency) {
			pbn.SetCurrency(nil)
		},
		"fail, empty nonce": func(pbn *protos.Currency) {
			pbn.SetCurrency([]byte{})
		},
		"fail, invalid currency": func(pbn *protos.Currency) {
			pbn.SetCurrency([]byte{4})
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			pbc := &protos.Currency{}
			pbc.SetCurrency(bytes.Repeat([]byte{'1'}, anonpay.NonceLen))

			tc(pbc)

			c := currency.Value{}
			err := c.UnmarshalProto(pbc)
			require.Error(t, err)
		})
	}

	t.Run("fail, unmarshal nil", func(t *testing.T) {
		c := &currency.Value{}
		err := c.UnmarshalProto(nil)
		require.Error(t, err)
	})
}
