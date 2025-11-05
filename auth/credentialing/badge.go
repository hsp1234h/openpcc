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

package credentialing

import (
	"encoding/base64"
	"fmt"

	"github.com/openpcc/openpcc/gen/protos"
	"google.golang.org/protobuf/proto"
)

// Badge represents a set of permissions for a given user
type Badge struct {
	Credentials Credentials
	Signature   []byte
}

func (b *Badge) MarshalProto() (*protos.Badge, error) {
	creds, err := b.Credentials.MarshalProto()
	if err != nil {
		return nil, err
	}
	return protos.Badge_builder{
		Credentials: creds,
		Signature:   b.Signature,
	}.Build(), nil
}

func (b *Badge) UnmarshalProto(badge *protos.Badge) error {
	err := b.Credentials.UnmarshalProto(badge.GetCredentials())
	if err != nil {
		return err
	}

	b.Signature = badge.GetSignature()
	return nil
}

func (b *Badge) MarshalText() ([]byte, error) {
	badgeProto, err := b.MarshalProto()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal badge: %w", err)
	}
	badgeBytes, err := proto.Marshal(badgeProto)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal badge: %w", err)
	}
	return badgeBytes, nil
}

func (b *Badge) UnmarshalText(text []byte) error {
	badgeProto := protos.Badge{}
	err := proto.Unmarshal(text, &badgeProto)
	if err != nil {
		return fmt.Errorf("failed to unmarshal badge: %w", err)
	}
	err = b.UnmarshalProto(&badgeProto)
	if err != nil {
		return err
	}
	return nil
}

func (b *Badge) Serialize() (string, error) {
	badgeBytes, err := b.MarshalText()
	if err != nil {
		return "", err
	}
	badgeB64 := base64.StdEncoding.EncodeToString(badgeBytes)
	return badgeB64, nil
}

func (b *Badge) Deserialize(serializedBadge string) error {
	badgeBytes, err := base64.StdEncoding.DecodeString(serializedBadge)
	if err != nil {
		return err
	}
	return b.UnmarshalText(badgeBytes)
}
