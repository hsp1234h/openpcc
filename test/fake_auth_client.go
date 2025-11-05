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

package test

import (
	"context"
	"errors"

	"github.com/confidentsecurity/ohttp"
	"github.com/openpcc/openpcc/anonpay"
	authclient "github.com/openpcc/openpcc/auth/client"
	"github.com/openpcc/openpcc/auth/credentialing"
	"github.com/openpcc/openpcc/gateway"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
)

type FakeAuthClient struct {
	RouterURLFunc           func() string
	OHTTPKeyConfigs         ohttp.KeyConfigs
	OHTTPKeyRotationPeriods []gateway.KeyRotationPeriodWithID
}

func (m *FakeAuthClient) RemoteConfig() authclient.RemoteConfig {
	return authclient.RemoteConfig{
		RouterURL:               m.RouterURLFunc(),
		BankURL:                 "",
		OHTTPRelayURLs:          []string{"fake.relay.invalid"},
		OHTTPKeyConfigs:         m.OHTTPKeyConfigs,
		OHTTPKeyRotationPeriods: m.OHTTPKeyRotationPeriods,
	}
}

//nolint:revive
func (c *FakeAuthClient) GetAttestationToken(ctx context.Context) (*anonpay.BlindedCredit, error) {
	return nil, errors.New("not implemented")
}

//nolint:revive
func (c *FakeAuthClient) GetCredit(ctx context.Context, amountNeeded int64) (*anonpay.BlindedCredit, error) {
	return nil, errors.New("not implemented")
}

//nolint:revive
func (c *FakeAuthClient) PutCredit(ctx context.Context, finalCredit *anonpay.BlindedCredit) error {
	return nil
}

//nolint:revive
func (c *FakeAuthClient) GetBadge(ctx context.Context) (credentialing.Badge, error) {
	return credentialing.Badge{
		Credentials: credentialing.Credentials{Models: []string{"llama3.2:1b"}},
	}, nil
}

func (c *FakeAuthClient) Payee() *anonpay.Payee {
	return anonpaytest.MustNewPayee()
}
