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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/memberlist"
)

// AddrFinder finds addresses of other nodes in the memberlist gossip network.
type AddrFinder interface {
	FindAddrs(ctx context.Context) ([]string, error)
}

// App is an app that participates as a member in a memberlist gossip network.
type App struct {
	config     *Config
	mlConfig   *memberlist.Config
	ctx        context.Context
	cancelFunc context.CancelFunc
	joinable   atomic.Bool
	addrFinder AddrFinder

	delegate *delegate
}

func NewApp(cfg *Config, id uuid.UUID, opts ...Option) (*App, error) {
	if cfg.MaxPeersToJoin < 1 {
		return nil, fmt.Errorf("invalid max peers to join, want at least 1 got %d", cfg.MaxPeersToJoin)
	}

	if cfg.PeerDiscoveryInterval < 0 {
		return nil, fmt.Errorf("negative peer discovery interval %v", cfg.PeerDiscoveryInterval)
	}

	if cfg.PeerDiscoveryThreshold < 1 {
		return nil, fmt.Errorf("invalid peer discovery threshold, want at least 1 got %d", cfg.PeerDiscoveryThreshold)
	}

	delegate := newDelegate(id)
	mlCfg, err := cfg.MemberlistConfig.toActualConfig(id, delegate)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	a := &App{
		config:     cfg,
		mlConfig:   mlCfg,
		ctx:        ctx,
		cancelFunc: cancel,
		joinable:   atomic.Bool{},
		delegate:   delegate,
	}

	for _, opt := range opts {
		err := opt(a)
		if err != nil {
			return nil, err
		}
	}

	return a, nil
}

func (a *App) LocalNodeID() uuid.UUID {
	return a.delegate.localID
}

// IsJoinable indicates the app is running and can be joined via memberlist.
func (a *App) IsJoinable() bool {
	return a.joinable.Load()
}

func (a *App) Run() error {
	a.joinable.Store(false)

	slog.Info("creating gossip listeners")
	// create the local listeners for the gossip cluster
	list, err := memberlist.Create(a.mlConfig)
	if err != nil {
		return fmt.Errorf("failed to create memberlist: %w", err)
	}

	// ready to join
	a.joinable.Store(true)

	// begin the join loop if configured to join a cluster.
	if a.configuredToJoin() {
		go a.joinLoop(list)
	}

	// wait to be done.
	<-a.ctx.Done()

	// Broadcast the leave message to other nodes but ignore the timeout error. It will always
	// appear in single-node clusters as there's no-one to receive it.
	//
	// Need to do a string check as this error isn't exported in any way.
	err = list.Leave(a.config.LeaveTimeout)
	if err != nil {
		if !strings.Contains(err.Error(), "timeout waiting for leave broadcast") {
			return fmt.Errorf("failed to leave gossip cluster: %w", err)
		}
		slog.Info("timeout waiting for leave broadcast", "memberlist_members", list.NumMembers(), "error", err.Error())
	}

	// Shutdown actually stops memberlist traffic.
	err = list.Shutdown()
	if err != nil {
		return fmt.Errorf("failed to shutdown the memberlist: %w", err)
	}
	a.joinable.Store(false)

	// Wait for delegate to be done.
	err = a.delegate.Close()
	if err != nil {
		return fmt.Errorf("failed to wait for delegate to close: %w", err)
	}

	return nil
}

// BroadcastMessage is used to broadcast a message across the
// gossip network this app is a member of. There is no guarantee
// that this message will ever arrive at any peers, as it's transmit
// via UDP.
func (a *App) BroadcastMessage(msg []byte) {
	if a.ctx.Err() != nil {
		return
	}

	a.delegate.BroadcastMessage(msg)
}

func (a *App) Shutdown(context.Context) error {
	a.joinable.Store(false)
	a.cancelFunc()
	return nil
}

func (a *App) configuredToJoin() bool {
	return len(a.config.JoinAddrs) > 0 || a.addrFinder != nil
}

// joinLoop periodically attempts to join other nodes if the app doesn't know about
// enough peer nodes.
func (a *App) joinLoop(list *memberlist.Memberlist) {
	join := func() {
		// When we know about enough members (peers + self), don't do anything.
		count := list.NumMembers()
		threshold := a.config.PeerDiscoveryThreshold + 1
		if count >= threshold {
			slog.Info("knows about peers", "member_count", count, "threshold", threshold)
			return
		}
		addrs, err := a.joinAttempt(list)
		if err != nil {
			slog.Warn("join attempt failed", "error", err)
			return
		}
		slog.Info("successfully joined", "addrs", strings.Join(addrs, ","))
	}

	// immediately attempt to join.
	join()

	ticker := time.NewTicker(a.config.PeerDiscoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// then join every interval.
			join()
			continue
		case <-a.ctx.Done():
			// stop the loop when the app is shutting down.
			return
		}
	}
}

func (a *App) joinAttempt(list *memberlist.Memberlist) ([]string, error) {
	// source the addresses we want to join.
	var addrs []string
	if len(a.config.JoinAddrs) > 0 {
		addrs = append(addrs, a.config.JoinAddrs...)
	}

	if a.addrFinder != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		found, err := a.addrFinder.FindAddrs(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to find addresses: %w", err)
		}

		// sort to make this somewhat stable. This results in some nodes knowing
		// about all the nodes before others, so that they can spread this complete-ish
		// information via the gossip network.
		slices.Sort(found)

		for i := 0; i < a.config.MaxPeersToJoin && i < len(found); i++ {
			addrs = append(addrs, found[i])
		}
	}

	if len(addrs) == 0 {
		return nil, errors.New("no addresses to join")
	}

	_, err := list.Join(addrs)
	if err != nil {
		return nil, fmt.Errorf("failed to join cluster: %w", err)
	}

	return addrs, nil
}

type slogAdapter struct {
	logger *slog.Logger
}

func (s *slogAdapter) Write(p []byte) (n int, err error) {
	// trim trailing newline
	msg := string(bytes.TrimRight(p, "\n"))
	switch {
	case strings.HasPrefix(msg, "[DEBUG]"):
		s.logger.Debug(strings.TrimPrefix(msg, "[DEBUG] "))
	case strings.HasPrefix(msg, "[INFO]"):
		s.logger.Info(strings.TrimPrefix(msg, "[INFO] "))
	case strings.HasPrefix(msg, "[WARN]"):
		s.logger.Warn(strings.TrimPrefix(msg, "[WARN] "))
	case strings.HasPrefix(msg, "[ERR]"):
		s.logger.Error(strings.TrimPrefix(msg, "[ERR] "))
	default:
		// If we can't determine the level, default to Info
		s.logger.Info(msg)
	}

	return len(p), nil
}
