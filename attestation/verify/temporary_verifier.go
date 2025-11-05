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
package verify

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	ev "github.com/openpcc/openpcc/attestation/evidence"

	"github.com/golang-jwt/jwt/v5"
)

type TemporaryVerifier struct {
	jwtParser *jwt.Parser
}

func NewTemporaryVerifier() *TemporaryVerifier {
	return &TemporaryVerifier{
		jwtParser: jwt.NewParser(),
	}
}

//revive:disable:exported
func (v *TemporaryVerifier) VerifyComputeNode(_ context.Context, evidence ev.SignedEvidenceList) (*ev.ComputeData, error) {
	if len(evidence) == 0 {
		return nil, errors.New("no evidence")
	}

	// only consider the first evidence piece.
	piece := evidence[0]
	parsedToken, _, err := v.jwtParser.ParseUnverified(piece.ToJWT(), &SEVSNPClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	sevsnpClaims, ok := parsedToken.Claims.(*SEVSNPClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected token type: %T", parsedToken.Claims)
	}

	return &sevsnpClaims.Sevsnp.ComputeData, nil
}

//revive:enable:exported

type SevsnpClaimsBody struct {
	AttesterType string         `json:"attester_type"`
	ComputeData  ev.ComputeData `json:"sevsnp_runtime_data"`
}

type SEVSNPClaims struct {
	Issuer               string  `json:"iss"`
	ExpirationTimeNumber float64 `json:"exp"`
	IssuedAtNumber       float64 `json:"iat"`
	NotBeforeNumber      float64 `json:"nbf"`
	Subject              string  `json:"sub"`
	AudienceString       string  `json:"aud"`

	Sevsnp SevsnpClaimsBody `json:"sevsnp"`
}

func timeFromJWT(f float64) time.Time {
	round, frac := math.Modf(f)
	return time.Unix(int64(round), int64(frac*1e9))
}

func (s SEVSNPClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	t := timeFromJWT(s.ExpirationTimeNumber)
	return jwt.NewNumericDate(t), nil
}

func (s SEVSNPClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	t := timeFromJWT(s.IssuedAtNumber)
	return jwt.NewNumericDate(t), nil
}
func (s SEVSNPClaims) GetNotBefore() (*jwt.NumericDate, error) {
	t := timeFromJWT(s.NotBeforeNumber)
	return jwt.NewNumericDate(t), nil
}
func (s SEVSNPClaims) GetIssuer() (string, error) {
	return s.Issuer, nil
}
func (s SEVSNPClaims) GetSubject() (string, error) {
	return s.Subject, nil
}
func (SEVSNPClaims) GetAudience() (jwt.ClaimStrings, error) {
	return nil, errors.New("not implemented")
}
