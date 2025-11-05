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
	"fmt"
	"log"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/memberlist"
)

type Config struct {
	// MemberlistConfig is config for the memberlist library that undergirds our gossiping
	MemberlistConfig MemberlistConfig `yaml:"memberlist"`
	// LeaveTimeout is how long to wait for the Leave message to succeed when leaving the gossip group
	LeaveTimeout time.Duration `yaml:"leave_timeout"`
	// JoinAddrs are explicit nodes to join, added to the ones found by dynamically searching
	JoinAddrs []string `yaml:"join_addrs"`
	// PeerDiscoveryInterval is the interval at which a gossip app will look for other
	// nodes to join. It will only do this when it's configured to join a network,
	// and knows about fewer than PeerDiscoveryThreshold nodes (excluding itself).
	PeerDiscoveryInterval  time.Duration `yaml:"peer_discovery_interval"`
	PeerDiscoveryThreshold int           `yaml:"peer_discovery_threshold"`
	// MaxPeersToJoin is the maximum number of found addresses that are joined.
	// Only used if an AddrFinder is configured.
	MaxPeersToJoin int `yaml:"max_found_join_addrs"`
}

func DefaultConfig() *Config {
	return &Config{
		MemberlistConfig: MemberlistConfig{
			Profile: "wan",
		},
		LeaveTimeout:           time.Second * 10,
		PeerDiscoveryInterval:  time.Second * 30,
		PeerDiscoveryThreshold: 1, // stop discovering when you know about 1 other node.
		MaxPeersToJoin:         2, // join at most two other nodes at a time.
	}
}

type MemberlistConfig struct {
	// Profile is the profile used for memberlist gossip configuration.
	// Should be one of `wan`, `lan` or `local`. Defaults to `wan`.
	//
	// All other options in this section will default to values for the
	// provided profile.
	//
	// See the memberlist documentation for what the different options do:
	// https://pkg.go.dev/github.com/hashicorp/memberlist#Config
	Profile string `yaml:"profile"`

	BindAddr                *string        `yaml:"bind_addr"`
	BindPort                *int           `yaml:"bind_port"`
	AdvertiseAddr           *string        `yaml:"advertise_addr"`
	AdvertisePort           *int           `yaml:"advertise_port"`
	ProtocolVersion         *byte          `yaml:"protocol_version"`
	TCPTimeout              *time.Duration `yaml:"tcp_timeout"`
	IndirectChecks          *int           `yaml:"indirect_checks"`
	RetransmitMult          *int           `yaml:"retransmit_mult"`
	SuspicionMult           *int           `yaml:"suspicion_mult"`
	SuspicionMaxTimeoutMult *int           `yaml:"suspicion_max_timeout_mult"`
	PushPullInterval        *time.Duration `yaml:"push_pull_interval"`
	ProbeTimeout            *time.Duration `yaml:"probe_timeout"`
	ProbeInterval           *time.Duration `yaml:"probe_interval"`
	DisableTCPPings         *bool          `yaml:"disable_tcp_pings"`
	AwarenessMaxMultiplier  *int           `yaml:"awareness_max_multiplier"`
	GossipNodes             *int           `yaml:"gossip_nodes"`
	GossipInterval          *time.Duration `yaml:"gossip_interval"`
	EnableCompression       *bool          `yaml:"enable_compression"`
	DNSConfigPath           *string        `yaml:"dns_config_path"`
	HandoffQueueDepth       *int           `yaml:"handoff_queue_depth"`
	UDPBufferSize           *int           `yaml:"udp_buffer_size"`
	QueueCheckInterval      *time.Duration `yaml:"queue_check_interval"`
}

func (c *MemberlistConfig) toActualConfig(nodeID uuid.UUID, delegate *delegate) (*memberlist.Config, error) {
	var cfg *memberlist.Config
	switch c.Profile {
	case "local":
		cfg = memberlist.DefaultLocalConfig()
	case "wan":
		cfg = memberlist.DefaultWANConfig()
	case "lan":
		cfg = memberlist.DefaultLANConfig()
	default:
		return nil, fmt.Errorf("unknown memberlist profile: %s", c.Profile)
	}

	// defaults are all set, now handle any overrides

	cfg.BindAddr = configOpt(cfg.BindAddr, c.BindAddr)
	cfg.BindPort = configOpt(cfg.BindPort, c.BindPort)
	cfg.AdvertiseAddr = configOpt(cfg.AdvertiseAddr, c.AdvertiseAddr)
	cfg.AdvertisePort = configOpt(cfg.AdvertisePort, c.AdvertisePort)
	cfg.ProtocolVersion = configOpt(cfg.ProtocolVersion, c.ProtocolVersion)
	cfg.TCPTimeout = configOpt(cfg.TCPTimeout, c.TCPTimeout)
	cfg.IndirectChecks = configOpt(cfg.IndirectChecks, c.IndirectChecks)
	cfg.RetransmitMult = configOpt(cfg.RetransmitMult, c.RetransmitMult)
	cfg.SuspicionMult = configOpt(cfg.SuspicionMult, c.SuspicionMult)
	cfg.SuspicionMaxTimeoutMult = configOpt(cfg.SuspicionMaxTimeoutMult, c.SuspicionMaxTimeoutMult)
	cfg.PushPullInterval = configOpt(cfg.PushPullInterval, c.PushPullInterval)
	cfg.ProbeTimeout = configOpt(cfg.ProbeTimeout, c.ProbeTimeout)
	cfg.ProbeInterval = configOpt(cfg.ProbeInterval, c.ProbeInterval)
	cfg.DisableTcpPings = configOpt(cfg.DisableTcpPings, c.DisableTCPPings)
	cfg.AwarenessMaxMultiplier = configOpt(cfg.AwarenessMaxMultiplier, c.AwarenessMaxMultiplier)
	cfg.GossipNodes = configOpt(cfg.GossipNodes, c.GossipNodes)
	cfg.GossipInterval = configOpt(cfg.GossipInterval, c.GossipInterval)
	cfg.EnableCompression = configOpt(cfg.EnableCompression, c.EnableCompression)
	cfg.DNSConfigPath = configOpt(cfg.DNSConfigPath, c.DNSConfigPath)
	cfg.HandoffQueueDepth = configOpt(cfg.HandoffQueueDepth, c.HandoffQueueDepth)
	cfg.UDPBufferSize = configOpt(cfg.UDPBufferSize, c.UDPBufferSize)
	cfg.QueueCheckInterval = configOpt(cfg.QueueCheckInterval, c.QueueCheckInterval)

	// set our app specific functionality.
	// set the rest of the config.
	cfg.Name = nodeID.String()

	// adapt log output to our format
	cfg.Logger = log.New(&slogAdapter{
		logger: slog.Default(),
	}, "", 0)

	cfg.Delegate = delegate
	cfg.Events = delegate

	return cfg, nil
}

func configOpt[T any](fallback T, val *T) T {
	if val == nil {
		return fallback
	}
	return *val
}
