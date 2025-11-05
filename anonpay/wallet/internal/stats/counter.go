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

package stats

import (
	"sync"

	"github.com/openpcc/openpcc/anonpay/currency"
)

// TransferCount is a reading of a [TransferCounter].
type TransferCount struct {
	Count int64
	// Amount is the full amount of credits including rounding gain.
	Amount  int64
	Credits int64
	// RoundingGain is the amount gained due to rounding.
	RoundingGain int64
}

func (c TransferCount) AmountNoRounding() int64 {
	return c.Amount - c.RoundingGain
}

// CreditCounter is the total amount represented by a specific number of credits.
type CreditCount struct {
	Amount  int64
	Credits int64
}

func CreditCountBetween(produced TransferCount, consumed ...TransferCount) CreditCount {
	ac := CreditCount{
		Amount:  produced.Amount,
		Credits: produced.Credits,
	}
	for _, c := range consumed {
		ac.Amount -= c.AmountNoRounding()
		ac.Credits -= c.Credits
	}

	return ac
}

func SumTransferCounts(ccs ...TransferCount) TransferCount {
	var out TransferCount
	for _, cc := range ccs {
		out.Count += cc.Count
		out.Amount += cc.Amount
		out.Credits += cc.Credits
		out.RoundingGain += cc.RoundingGain
	}
	return out
}

func SubTransferCounts(c1 TransferCount, c2 TransferCount) TransferCount {
	return TransferCount{
		Count:        c1.Count - c2.Count,
		Amount:       c1.Amount - c2.Amount,
		Credits:      c1.Credits - c2.Credits,
		RoundingGain: c1.RoundingGain - c2.RoundingGain,
	}
}

// TransferCounter counts transfers made by the wallet. It's safe
// to be called from multiple goroutines.
type TransferCounter struct {
	mu *sync.RWMutex
	c  TransferCount
}

func NewTransferCounter() *TransferCounter {
	return &TransferCounter{
		mu: &sync.RWMutex{},
		c:  TransferCount{},
	}
}

func (c *TransferCounter) Read() TransferCount {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c
}

func (c *TransferCounter) Count(roundingGain int64, amounts ...currency.Value) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.c.Count++
	c.c.Credits += int64(len(amounts))
	c.c.Amount += sumAmounts(amounts...)
	c.c.RoundingGain += roundingGain
}

func sumAmounts(amounts ...currency.Value) int64 {
	sum := int64(0)
	for _, amount := range amounts {
		sum += amount.AmountOrZero()
	}
	return sum
}
