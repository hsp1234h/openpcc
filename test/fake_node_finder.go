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

	"github.com/openpcc/openpcc"
	"github.com/openpcc/openpcc/auth/credentialing"
	"github.com/openpcc/openpcc/tags"
)

type FakeNodeFinder struct {
	FindVerifiedNodesFunc func(ctx context.Context, maxNodes int, tags tags.Tags) ([]openpcc.VerifiedNode, error)
	CloseCalls            int
}

//nolint:revive
func (f *FakeNodeFinder) FindVerifiedNodes(ctx context.Context, maxNodes int, tags tags.Tags) ([]openpcc.VerifiedNode, error) {
	if f.FindVerifiedNodesFunc != nil {
		return f.FindVerifiedNodesFunc(ctx, maxNodes, tags)
	}

	return nil, nil
}

//nolint:revive
func (f *FakeNodeFinder) ListCachedVerifiedNodes() ([]openpcc.VerifiedNode, error) {
	return []openpcc.VerifiedNode{}, nil
}

//nolint:revive
func (f *FakeNodeFinder) GetBadge(ctx context.Context) (credentialing.Badge, error) {
	return credentialing.Badge{
		Credentials: credentialing.Credentials{Models: []string{"llama3.2:1b"}},
	}, nil
}

func (f *FakeNodeFinder) Close() error {
	f.CloseCalls++
	return nil
}
