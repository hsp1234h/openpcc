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

package keyrotation

import (
	"errors"
	"time"
)

const (
	// DefaultKeyExpirationMonths is the default key expiration period in months.
	// Keys are typically valid for 6 months.
	DefaultKeyExpirationMonths = 6

	// DefaultKeyActivationDays is the default key activation period in days.
	// Keys are typically valid 7 days after their corresponding secret is created.
	DefaultKeyActivationDays = 7
)

var (
	ErrorKeyNotYetActive = errors.New("key not yet active")
	ErrorKeyExpired      = errors.New("key expired")
)

// Period represents a key rotation period, which is additional, confsec-specific metadata for a key.
// The goal of this type is to support key rotation more generically for multiple key types.
type Period struct {
	// ActiveFrom is the time from which the key is active (valid for use) and will be accepted.
	ActiveFrom time.Time `json:"active_from"`

	// ActiveUntil is the time after which the key is no longer active and will be rejected (e.g. key expiration).
	ActiveUntil time.Time `json:"active_until"`
}

// NewPeriodFromSecretCreation creates a new key rotation period based on the creation time
// of the underlying key secret, and the default key activation and expiration periods.
func NewPeriodFromSecretCreation(creationTime time.Time) Period {
	return NewPeriodStartingAt(creationTime.AddDate(0, 0, DefaultKeyActivationDays))
}

// NewPeriodStartingAt creates a new key rotation period that starts at the given time,
// and expires after the default period.
func NewPeriodStartingAt(activeFrom time.Time) Period {
	return Period{
		ActiveFrom:  activeFrom,
		ActiveUntil: activeFrom.AddDate(0, DefaultKeyExpirationMonths, 0),
	}
}

func (p Period) IsActive() bool {
	return time.Now().After(p.ActiveFrom) && !p.IsExpired()
}

func (p Period) IsExpired() bool {
	return time.Now().After(p.ActiveUntil)
}

func (p Period) CheckIfActive() error {
	if p.IsExpired() {
		return ErrorKeyExpired
	} else if !p.IsActive() {
		return ErrorKeyNotYetActive
	}
	return nil
}
