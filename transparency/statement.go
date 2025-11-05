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

package transparency

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"

	spb "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

type StatementSubject struct {
	Name   string
	Digest map[string]string
}

// Statement is used to sign bundles with multiple subjects and custom meta data (a predicate).
//
// Format is based on:
// https://github.com/in-toto/attestation/blob/v0.1.0/spec/README.md#statement
type Statement struct {
	Subject       []StatementSubject
	PredicateType string
	Predicate     map[string]any
}

func (s StatementSubject) hexSha256Digest() string {
	digest, ok := s.Digest["sha256"]
	if !ok {
		// should not happen in a valid statement.
		return ""
	}
	return digest
}

func (s StatementSubject) Sha256Match(data []byte) (bool, error) {
	hash := sha256.Sum256(data)
	hexDigest, ok := s.Digest["sha256"]
	if !ok {
		return false, errors.New("subject is missing sha256 digest")
	}
	digestHash, err := hex.DecodeString(hexDigest)
	if err != nil {
		return false, fmt.Errorf("failed to decode subject hash from hex: %w", err)
	}
	return bytes.Equal(digestHash, hash[:]), nil
}

func (s *Statement) Validate() error {
	if s == nil {
		return errors.New("nil statement")
	}

	if len(s.Subject) == 0 {
		return errors.New("missing subject")
	}

	seen := make(map[string]struct{}, len(s.Subject))
	for _, subject := range s.Subject {
		_, ok := seen[subject.Name]
		if ok {
			return fmt.Errorf("duplicate subject %s", subject.Name)
		}
		seen[subject.Name] = struct{}{}

		digest := subject.hexSha256Digest()
		if len(digest) == 0 {
			return errors.New("missing sha256 digest")
		}

		rawHash, err := hex.DecodeString(digest)
		if err != nil {
			return fmt.Errorf("invalid sha256 digest, not hex-encoded: %w", err)
		}
		err = validateSha256Hash(rawHash)
		if err != nil {
			return err
		}
	}

	err := validatePredicateType(s.PredicateType)
	if err != nil {
		return err
	}

	return nil
}

func validateSha256Hash(d []byte) error {
	if len(d) != 32 {
		return fmt.Errorf("invalid sha256 digest, want %d bytes, got %d bytes", 32, len(d))
	}
	return nil
}

func validatePredicateType(s string) error {
	ptURL, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("invalid predicate type: %w", err)
	}
	if ptURL.Scheme == "" {
		return errors.New("predicate type is missing scheme")
	}
	if ptURL.Host == "" {
		return errors.New("predicate type is missing host")
	}

	return nil
}

// NewStatement creates a new statement for the given subjects and predicate. Subject keys are
// interpreted as subject names, subject values are hashed and used for the digest.
func NewStatement(subject map[string][]byte, predicateType string, predicate map[string]any) *Statement {
	sub := make([]StatementSubject, 0, len(subject))
	for name, data := range subject {
		hash := sha256.Sum256(data)
		sub = append(sub, StatementSubject{
			Name: name,
			Digest: map[string]string{
				"sha256": hex.EncodeToString(hash[:]),
			},
		})
	}

	statement := &Statement{
		Subject:       sub,
		PredicateType: predicateType,
		Predicate:     predicate,
	}

	return statement
}

// MarshalJSON marshals the statement to a json object suitable for use as a
// application/vnd.in-toto+json payload.
func (s *Statement) MarshalJSON() ([]byte, error) {
	sub := make([]*spb.ResourceDescriptor, 0, len(s.Subject))
	for _, subject := range s.Subject {
		sub = append(sub, &spb.ResourceDescriptor{
			Name:   subject.Name,
			Digest: subject.Digest,
		})
	}

	predicate, err := structpb.NewStruct(s.Predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to create protobuf struct: %w", err)
	}

	// first convert to the appropriate protobuf.
	pb := &spb.Statement{
		Type:          spb.StatementTypeUri,
		Subject:       sub,
		PredicateType: s.PredicateType,
		Predicate:     predicate,
	}

	// verify the protobuf is valid.
	err = pb.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid statement: %w", err)
	}

	data, err := protojson.Marshal(pb)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal to json: %w", err)
	}

	return data, nil
}

func (s *Statement) UnmarshalProto(pb *spb.Statement) error {
	s.Subject = make([]StatementSubject, 0, len(pb.Subject))
	for _, sub := range pb.GetSubject() {
		s.Subject = append(s.Subject, StatementSubject{
			Name:   sub.GetName(),
			Digest: sub.GetDigest(),
		})
	}
	s.PredicateType = pb.GetPredicateType()
	s.Predicate = pb.Predicate.AsMap()

	return nil
}
