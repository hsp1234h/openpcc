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

package statements

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/confidentsecurity/ohttp"
	"github.com/openpcc/openpcc/gateway"
	"github.com/openpcc/openpcc/transparency"
)

const OHTTPKeyConfigsPredicateType = "https://confident.security/v2/ohttp-keys"

func VerifyOHTTPKeyConfigsBundle(b []byte, v *transparency.Verifier, idPolicy transparency.IdentityPolicy) (*transparency.Statement, transparency.BundleMetadata, error) {
	return v.VerifyStatementPredicate(b, "ohttpKeys", idPolicy)
}

// FromOHTTPKeyConfigs creates a new statement for the given key configs and rotation periods.
// keyRotationPeriods contains rotation period for each key in the key configs ("keyed" by ID) and must be the same length.
func FromOHTTPKeyConfigs(keyConfigs ohttp.KeyConfigs, keyRotationPeriods []gateway.KeyRotationPeriodWithID) (*transparency.Statement, error) {
	msg, err := keyConfigs.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key config to binary: %w", err)
	}

	keyRotationPeriodsMsg, err := json.Marshal(keyRotationPeriods)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key rotation periods to json: %w", err)
	}

	// subject is the data that will get hashed and signed.
	subject := map[string][]byte{
		"ohttp-keys":           msg,
		"key-rotation-periods": keyRotationPeriodsMsg,
	}

	// predicate contains claims made by this statement.
	predicate := map[string]any{
		"ohttpKeys":          base64.StdEncoding.EncodeToString(msg),
		"keyRotationPeriods": base64.StdEncoding.EncodeToString(keyRotationPeriodsMsg),
	}

	return transparency.NewStatement(subject, OHTTPKeyConfigsPredicateType, predicate), nil
}

func ToOHTTPKeyConfigs(statement *transparency.Statement) (ohttp.KeyConfigs, []gateway.KeyRotationPeriodWithID, error) {
	if statement.PredicateType != OHTTPKeyConfigsPredicateType {
		return nil, nil, fmt.Errorf("invalid predicate type. want %s, got %s", OHTTPKeyConfigsPredicateType, statement.PredicateType)
	}

	keysRaw, keyRotationPeriodsRaw, err := signedOHTTPKeysRaw(statement)
	if err != nil {
		return nil, nil, err
	}

	var keys ohttp.KeyConfigs
	err = keys.UnmarshalBinary(keysRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal ohttp key configs from binary: %w", err)
	}

	var keyRotationPeriods []gateway.KeyRotationPeriodWithID
	err = json.Unmarshal(keyRotationPeriodsRaw, &keyRotationPeriods)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal key rotation periods from json: %w", err)
	}

	return keys, keyRotationPeriods, nil
}

func signedOHTTPKeysRaw(statement *transparency.Statement) ([]byte, []byte, error) {
	if len(statement.Subject) != 2 {
		return nil, nil, fmt.Errorf("expected 2 subjects, got %d subjects", len(statement.Subject))
	}
	var keysSubject, keyRotationPeriodsSubject *transparency.StatementSubject
	for _, subject := range statement.Subject {
		switch subject.Name {
		case "ohttp-keys":
			keysSubject = &subject
		case "key-rotation-periods":
			keyRotationPeriodsSubject = &subject
		default:
			return nil, nil, fmt.Errorf("unexpected subject name %s", subject.Name)
		}
	}

	if keysSubject == nil || keyRotationPeriodsSubject == nil {
		return nil, nil, errors.New("missing required subjects")
	}

	predicateVal, ok := statement.Predicate["ohttpKeys"]
	if !ok {
		return nil, nil, errors.New("missing ohttpKeys in predicate")
	}

	keysBase64, ok := predicateVal.(string)
	if !ok {
		return nil, nil, fmt.Errorf("expected a string but got a %#v", predicateVal)
	}

	keysRaw, err := base64.StdEncoding.DecodeString(keysBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to base64 decode raw ohttp keys: %w", err)
	}

	// Most important operation, this statement contains the signed key data, but it is up to us to verify that the hash actually matches.
	match, err := keysSubject.Sha256Match(keysRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("error matching hashes: %w", err)
	}
	if !match {
		return nil, nil, errors.New("raw ohttp key configs and statement digest don't match")
	}

	predicateVal, ok = statement.Predicate["keyRotationPeriods"]
	if !ok {
		return nil, nil, errors.New("missing keyRotationPeriods in predicate")
	}

	keyRotationPeriodsBase64, ok := predicateVal.(string)
	if !ok {
		return nil, nil, fmt.Errorf("expected a string but got a %#v", predicateVal)
	}

	keyRotationPeriodsRaw, err := base64.StdEncoding.DecodeString(keyRotationPeriodsBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to base64 decode raw ohttp key rotation periods: %w", err)
	}

	// Similar to above, verify that the hash in the key rotation periods statement matches the raw data.
	match, err = keyRotationPeriodsSubject.Sha256Match(keyRotationPeriodsRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("error matching hashes: %w", err)
	}
	if !match {
		return nil, nil, errors.New("raw ohttp key rotation periods and statement digest don't match")
	}

	return keysRaw, keyRotationPeriodsRaw, nil
}
