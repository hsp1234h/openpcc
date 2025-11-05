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

package gossip

import (
	"bytes"
	"fmt"

	"github.com/hashicorp/memberlist"
)

type Option func(a *App) error

func WithMessageHandler(h MessageHandler) Option {
	return func(a *App) error {
		a.delegate.messageHandler = h
		return nil
	}
}

func WithStateHandler(h StateHandler) Option {
	return func(a *App) error {
		a.delegate.stateHandler = h
		return nil
	}
}

func WithStateReader(r StateReader) Option {
	return func(a *App) error {
		a.delegate.stateReader = r
		return nil
	}
}

func WithLocalNodeMeta(b []byte) Option {
	return func(a *App) error {
		if len(b) > memberlist.MetaMaxSize {
			return fmt.Errorf("invalid local node meta, must be at most %d bytes, got %d", memberlist.MetaMaxSize, len(b))
		}
		a.delegate.localMeta = bytes.Clone(b)
		return nil
	}
}

func WithNodeHandler(h NodeHandler) Option {
	return func(a *App) error {
		a.delegate.nodeHandler = h
		return nil
	}
}

func WithExtraMemberlistConfig(modFunc func(cfg *memberlist.Config) error) Option {
	return func(a *App) error {
		if modFunc == nil {
			return nil
		}
		return modFunc(a.mlConfig)
	}
}

func WithAddrFinder(addrFinder AddrFinder) Option {
	return func(a *App) error {
		a.addrFinder = addrFinder
		return nil
	}
}
