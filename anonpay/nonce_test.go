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
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/gen/protos"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNonceUniqueWithSameTimestamp(t *testing.T) {
	nonce1, err := anonpay.RandomNonce()
	require.NoError(t, err)

	nonce2, err := anonpay.RandomNonce()
	require.NoError(t, err)

	require.InDelta(t, nonce1.Timestamp, nonce2.Timestamp, float64(anonpay.NonceTimeQuantizationSeconds))
	require.NotEqual(t, nonce1.Nonce, nonce2.Nonce)
}

func TestSafeNonceTimestamp(t *testing.T) {
	const NEXT = anonpay.NonceTimeQuantizationSeconds // The next period
	type timestampWithFactor struct {
		timestamp    int64
		randomFactor float64
	}
	roundsDown := []timestampWithFactor{
		{timestamp: 0, randomFactor: 0},
		{timestamp: 0, randomFactor: 0.5},
		{timestamp: 0, randomFactor: 1.0},
		{timestamp: 1, randomFactor: 0},
		{timestamp: 1, randomFactor: 0.5},
		{timestamp: 29, randomFactor: 0.0},
		{timestamp: 29, randomFactor: 0.5},
		{timestamp: 30, randomFactor: 0.0},
		{timestamp: 30, randomFactor: 0.5},
		{timestamp: 1799, randomFactor: 0.0},
		{timestamp: 1799, randomFactor: 0.5},
		{timestamp: 1800, randomFactor: 0.0},
		{timestamp: 1800, randomFactor: 0.5},
		{timestamp: NEXT - 1, randomFactor: 0.0},
	}
	roundsUpWithIncrement := []timestampWithFactor{
		{timestamp: 1, randomFactor: 1.0},
		{timestamp: 15, randomFactor: 1.0 - 14.9/NEXT},
		{timestamp: 15, randomFactor: 1.0},
		{timestamp: 29, randomFactor: 1.0},
	}
	roundsUp := []timestampWithFactor{
		{timestamp: 30, randomFactor: 1.0},
		{timestamp: 1799, randomFactor: 1.0},
		{timestamp: 1800, randomFactor: 1.0},
		{timestamp: 1801, randomFactor: 0.5},
		{timestamp: NEXT - 1, randomFactor: 1.0},
	}
	tests := []struct {
		name       string
		timestamps []timestampWithFactor
		assertion  func(t *testing.T, timestamp int64, unsafeIncrement bool)
	}{
		{
			name:       "rounds down",
			timestamps: roundsDown,
			assertion: func(t *testing.T, timestamp int64, unsafeIncrement bool) {
				require.Equal(t, int64(0), timestamp)
				require.False(t, unsafeIncrement)
			},
		},
		{
			name:       "rounds up",
			timestamps: roundsUp,
			assertion: func(t *testing.T, timestamp int64, unsafeIncrement bool) {
				require.Equal(t, int64(NEXT), timestamp)
				require.False(t, unsafeIncrement)
			},
		},
		{
			name:       "rounds up with increment",
			timestamps: roundsUpWithIncrement,
			assertion: func(t *testing.T, timestamp int64, unsafeIncrement bool) {
				require.Equal(t, int64(NEXT), timestamp)
				require.True(t, unsafeIncrement)
			},
		},
	}

	for _, test := range tests {
		for _, ts := range test.timestamps {
			t.Run(fmt.Sprintf("%d %s with factor %f", ts.timestamp, test.name, ts.randomFactor), func(t *testing.T) {
				timestamp, unsafeIncrement := anonpay.SafeNonceTimestamp(ts.timestamp, ts.randomFactor)
				test.assertion(t, timestamp, unsafeIncrement)
			})
		}
	}
}

func TestNonceMarshalUnmarshalProto(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		timestamp := time.Now().UTC().Round(0)
		pbn := &protos.Nonce{}
		pbn.SetNonce(bytes.Repeat([]byte{'1'}, anonpay.NonceLen))
		pbn.SetTimestamp(timestamppb.New(timestamp))

		want := &anonpay.Nonce{
			Nonce:     bytes.Repeat([]byte{'1'}, anonpay.NonceLen),
			Timestamp: timestamp.Unix(),
		}

		got := &anonpay.Nonce{}
		err := got.UnmarshalProto(pbn)
		require.NoError(t, err)
		require.Equal(t, want, got)

		// check again but with non-hardcoded pb
		pbn = got.MarshalProto()
		err = got.UnmarshalProto(pbn)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	failTests := map[string]func(*protos.Nonce){
		"fail, missing nonce": func(pbn *protos.Nonce) {
			pbn.ClearNonce()
		},
		"fail, nil nonce": func(pbn *protos.Nonce) {
			pbn.SetNonce(nil)
		},
		"fail, empty nonce": func(pbn *protos.Nonce) {
			pbn.SetNonce([]byte{})
		},
		"fail, nonce too short": func(pbn *protos.Nonce) {
			pbn.SetNonce(bytes.Repeat([]byte{'a'}, anonpay.NonceLen-1))
		},
		"fail, nonce too long": func(pbn *protos.Nonce) {
			pbn.SetNonce(bytes.Repeat([]byte{'a'}, anonpay.NonceLen+1))
		},
		"fail, missing timestamp": func(pbn *protos.Nonce) {
			pbn.ClearTimestamp()
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			timestamp := time.Now().UTC().Round(0)
			pbn := &protos.Nonce{}
			pbn.SetNonce(bytes.Repeat([]byte{'1'}, anonpay.NonceLen))
			pbn.SetTimestamp(timestamppb.New(timestamp))

			tc(pbn)

			n := &anonpay.Nonce{}
			err := n.UnmarshalProto(pbn)
			require.Error(t, err)
		})
	}

	t.Run("fail, unmarshal nil", func(t *testing.T) {
		n := &anonpay.Nonce{}
		err := n.UnmarshalProto(nil)
		require.Error(t, err)
	})
}
