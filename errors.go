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

package openpcc

import (
	"errors"
	"fmt"
)

// RouterError is an error from the router.
type RouterError struct {
	StatusCode int
	Message    string
}

func (e RouterError) Error() string {
	return fmt.Sprintf("router error, status code %d: %s", e.StatusCode, e.Message)
}

var (
	// ErrNotEnoughVerifiedNodes indicates a request could not be served because the client didn't
	// find any verified nodes to sent the request to.
	ErrNotEnoughVerifiedNodes = errors.New("did not find enough verified nodes to route the request")
	// ErrMaxCreditAmountViolated indicates a request or other operation attempted to set the credit amount
	// per request above the max credit amount.
	ErrMaxCreditAmountViolated = errors.New("maximum credit amount violated")
)
