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

package inmem_test

import (
	"testing"
	"time"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/noncelocking"
	"github.com/openpcc/openpcc/anonpay/noncelocking/inmem"
	"github.com/openpcc/openpcc/anonpay/noncelocking/testcontract"
)

func TestContract(t *testing.T) {
	testcontract.TestTicketLockerContract(t, func(t *testing.T) (noncelocking.TicketLockerContract, time.Duration, error) {
		return inmem.NewNonceLocker(), anonpay.NonceLifespanSeconds * time.Second, nil
	})
}
