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

package anonpay

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/openpcc/openpcc/gen/protos"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	NonceTimeQuantizationSeconds = 60 * 60      // NonceTimeQuantization represents the precision we round timestamps to for security.
	NonceLen                     = 16           // NonceLen is the size of our random portion.
	NonceMessageLen              = 8 + NonceLen // NonceMessageLen is length of a nonce when encoded as a message: 8 bytes for timestamp and 16 bytes for randomness.
	NonceMinimumSafeTimeSeconds  = 30           // NonceMinimumSafeTime is the time we need to wait before using a nonce with the next period's timestamp in the current period.
	// It should be set to a time period during which we expect multiple nonces to be issued.

	// NonceLifeSpan is 24 hours, plus double the quantization of nonces to allow for smearing of clock rollover.
	NonceLifespanSeconds = 60*60*24 + 2*NonceTimeQuantizationSeconds
	// NonceLockDuration is 300 seconds. Operations are expected to complete in this time.
	NonceLockDuration = 300 * time.Second
	// NonceMaxClockSkewSeconds is 30 seconds. Nonces more than this amount of time early are invalid.
	// There is some subtlety in how to interpret this as the threshold is rounded down to the nearest hour
	// after this skew is applied. e.g. at 11:00:25, a nonce with a timestamp of 10:00:00 is still valid.
	NonceMaxClockSkewSeconds = 30
)

// Nonce represents a timestamped piece of randomness which is used to identify and void a credit once it is spent.
type Nonce struct {
	Timestamp       int64
	Nonce           []byte
	UnsafeIncrement bool // UnsafeIncrement is true if the nonce timestamp is in the next period and we are near the beginning of the period. It should not be serialized.
}

// RandomNonce returns a random Nonce with a correctly rounded timestamp, or an error.
func RandomNonce() (Nonce, error) {
	randomFactor, err := RandFloat64()
	if err != nil {
		return Nonce{}, fmt.Errorf("failed to prepare nonce: %w", err)
	}
	timestamp, unsafeIncrement := SafeNonceTimestamp(time.Now().Unix(), randomFactor)

	nonce := Nonce{
		Timestamp:       timestamp,
		Nonce:           make([]byte, 16),
		UnsafeIncrement: unsafeIncrement,
	}
	_, err = rand.Read(nonce.Nonce)
	if err != nil {
		return Nonce{}, fmt.Errorf("failed to prepare nonce: %w", err)
	}
	return nonce, nil
}

// Nonce parsing errors.
var (
	ErrIncorrectLength = errors.New("incorrect length for nonce")
)

func (n Nonce) IsExpiredAt(timestamp time.Time) bool {
	minTime := timestamp.Add(-1 * time.Second * NonceMaxClockSkewSeconds)
	if n.Timestamp < RoundDownNonceTimestamp(minTime.Unix()) {
		return true
	}
	maxTime := timestamp.Add(time.Second * (NonceLifespanSeconds + NonceMaxClockSkewSeconds))
	if n.Timestamp > RoundDownNonceTimestamp(maxTime.Unix()) {
		return true
	}
	return false
}

// BlindBytes formats the nonce as a binary message that the Client and Server use in the blinding operations.
func (n Nonce) BlindBytes() ([]byte, error) {
	buf := make([]byte, 0, NonceMessageLen)
	buf, err := binary.Append(buf, binary.BigEndian, n.Timestamp)
	if err != nil {
		return nil, err
	}
	return append(buf, n.Nonce...), nil
}

func (n Nonce) MarshalBinary() ([]byte, error) {
	return proto.Marshal(n.MarshalProto())
}

func (n *Nonce) UnmarshalBinary(b []byte) error {
	pbn := &protos.Nonce{}
	err := proto.Unmarshal(b, pbn)
	if err != nil {
		return err
	}
	return n.UnmarshalProto(pbn)
}

func (n *Nonce) UnmarshalProto(pbn *protos.Nonce) error {
	if pbn == nil {
		return errors.New("nil protobuf")
	}
	if !pbn.HasNonce() || !pbn.HasTimestamp() {
		return errors.New("incomplete protobuf, needs both nonce and timestamp")
	}

	b := pbn.GetNonce()
	if len(b) != NonceLen {
		return fmt.Errorf("want nonce of length %d, but got %d: %w", 16, len(b), ErrIncorrectLength)
	}

	n.Nonce = b
	n.Timestamp = pbn.GetTimestamp().Seconds
	return nil
}

func (n Nonce) MarshalProto() *protos.Nonce {
	return protos.Nonce_builder{
		Timestamp: timestamppb.New(time.Unix(n.Timestamp, 0)),
		Nonce:     n.Nonce,
	}.Build()
}

func RoundDownNonceTimestamp(timestamp int64) int64 {
	// Round this down to the current hour
	timestamp /= NonceTimeQuantizationSeconds
	timestamp *= NonceTimeQuantizationSeconds
	return timestamp
}

/*
This code addresses an issue discovered in the original design.
Assume throughout, without loss of generality, that everyone's clocks are synchronized.

Consider if a nonce is created at exactly 11:00:00 and sent to the server to be signed.
If this credit is then spent immediately, the server will see that has a timestamp of 11:00:00,
and it will also know that only one nonce with that timestamp can have been issued, thus identifying the user.

A simple solution to this is to sometimes request the server sign nonces with a timestamp from the next hour.
There still needs to be some consideration of when to rollover to the next hour and what the server can deduce.

Consider if we create a nonce at 11:00:00 and send it to the server, but we chose to use the timestamp of 12:00:00.
Again, if this credit is spent immediately, the server will see that has a timestamp of 12:00:00, and know that
we are the only user who has issued a nonce with that timestamp.

So we can only use a nonce timestamped in the next period when we can be confident that other users will have also issued nonces
that could have been timestamped in the next period.

There are therefore three cases to consider:
 1. we issue a nonce for the current period. There are no further considerations.
 2. we issue a nonce for the next period. We do this with a probability proportional to how close to the end of the period we are.
 3. we issue a nonce for the next period but we are near the beginning of a period. In that case, we might be the first user
    to issue in the current period, so if we use this nonce, we may identify ourselves to the server.
    Therefore, we need to delay for a period of time before using this nonce. The delay needs to be long enough that
    we are confident that other users will have issued nonces in the current period. This delay is implemented in
    ClientCreditHandler#FinalizeBlindedCredit. It is also critical that the delay is not fixed, but instead until the
    cutoff time, otherwise the server could simply subtract the delay period.

In the third case, the client will see a delay of up to end of the cutoff period, but this will be rare because we are
rarely in the cutoff period (perhaps 30 seconds out of every hour), and we rarely choose to issue a next period nonce in
the cutoff period (a 30 in 3600 chance -> 1 in 120 chance). For those figures, the average delay is 0.0003 seconds.
*/
func SafeNonceTimestamp(timestamp int64, randomFactor float64) (int64, bool) {
	// Round this down to the current hour
	// But sometimes increment by NonceTimeQuantization to smear the rollover.
	roundedTimestamp := RoundDownNonceTimestamp(timestamp)
	nonQuantizedSeconds := timestamp - roundedTimestamp
	factor := 1.0 - float64(nonQuantizedSeconds)/float64(NonceTimeQuantizationSeconds)
	unsafeIncrement := false
	if factor < randomFactor {
		roundedTimestamp += NonceTimeQuantizationSeconds
		if nonQuantizedSeconds < NonceMinimumSafeTimeSeconds {
			unsafeIncrement = true
		}
	}
	return roundedTimestamp, unsafeIncrement
}
