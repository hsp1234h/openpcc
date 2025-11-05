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

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	// nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	ev "github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/httpfmt"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/tags"
)

type AddrFinder interface {
	FindAddrs(ctx context.Context) ([]string, error)
}

type Config struct {
	// Tags are what tags to advertise this compute node should be routed work for
	Tags []string `yaml:"tags"`
	// NodeTargetURL is the URL of this node, where the router should route inference requests
	NodeTargetURL string `yaml:"node_target_url"`
	// NodeHealthcheckURL is the healthcheck URL that the router should use to know that the node is up
	NodeHealthcheckURL string `yaml:"node_healthcheck_url"`
	// RouterBaseURL is the url of the router, where we should register
	RouterBaseURL string `yaml:"router_base_url"`
	// HeartbeatInterval determines how much time is between heartbeat requests.
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
}

func DefaultConfig() *Config {
	return &Config{
		Tags:               []string{},
		NodeTargetURL:      "",
		NodeHealthcheckURL: "",
		HeartbeatInterval:  1 * time.Minute,
	}
}

// Client runs as an agent on compute nodes. It is a client of the router that sends
// node events to the router(s).
type Client struct {
	mu        *sync.Mutex
	ctx       context.Context
	cancelCtx context.CancelFunc

	httpClient    *http.Client
	routerBaseURL *url.URL
	routerFinder  AddrFinder

	id          uuid.UUID
	routingInfo *RoutingInfo

	heartbeatInterval time.Duration
	eventIndex        int64
}

func New(id uuid.UUID, cfg *Config, evidence ev.SignedEvidenceList) (*Client, error) {
	ri := &RoutingInfo{
		Evidence: evidence,
	}

	if len(ri.Evidence) == 0 {
		return nil, errors.New("missing evidence")
	}

	var err error
	ri.Tags, err = tags.FromSlice(cfg.Tags)
	if err != nil {
		return nil, fmt.Errorf("invalid tags: %w", err)
	}

	ri.URL, err = parseAbsoluteURL(cfg.NodeTargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid node target url: %w", err)
	}

	ri.HealthcheckURL, err = parseAbsoluteURL(cfg.NodeHealthcheckURL)
	if err != nil {
		return nil, fmt.Errorf("invalid node healthcheck url: %w", err)
	}

	var routerBaseURL *url.URL
	if cfg.RouterBaseURL != "" {
		rBaseURL, err := parseAbsoluteURL(cfg.RouterBaseURL)
		if err != nil {
			return nil, fmt.Errorf("invalid router base url: %w", err)
		}
		routerBaseURL = &rBaseURL
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		mu:        &sync.Mutex{},
		ctx:       ctx,
		cancelCtx: cancel,

		httpClient: &http.Client{
			Timeout:   cfg.HeartbeatInterval / 2,
			Transport: otelutil.NewTransport(http.DefaultTransport),
		},
		routerBaseURL: routerBaseURL,

		id:          id,
		routingInfo: ri,

		heartbeatInterval: cfg.HeartbeatInterval,
		eventIndex:        0,
	}, nil
}

func (r *Client) RouterFinder(finder AddrFinder) {
	r.routerFinder = finder
}

func (r *Client) Run() error {
	// immediately try to send the first heartbeat.
	r.sendHeartbeat()

	// send a heartbeat every tick.
	ticker := time.NewTicker(r.heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.sendHeartbeat()
		case <-r.ctx.Done():
			return nil
		}
	}
}

func (r *Client) Shutdown(ctx context.Context) error {
	r.cancelCtx() // stop the Run method.
	slog.InfoContext(ctx, "sending shutdown event")
	// Propagate the shutdown context
	r.sendShutdown(ctx)
	return nil
}

func (r *Client) sendHeartbeat() {
	r.mu.Lock()
	defer func() {
		r.eventIndex++
		r.mu.Unlock()
	}()

	r.sendEvent(r.ctx, &NodeEvent{
		EventIndex: r.eventIndex,
		NodeID:     r.id,
		Timestamp:  time.Now(),
		Heartbeat: &Heartbeat{
			// For now we include the full routing info
			// in each heartbeat, in the future we might
			// want to only do this occasionally and let the
			// routers pull routing info when they're missing
			// it instead.
			RoutingInfo: r.routingInfo,
		},
	})
}

func (r *Client) sendShutdown(ctx context.Context) {
	r.mu.Lock()
	defer func() {
		r.eventIndex++
		r.mu.Unlock()
	}()

	now := time.Now()
	r.sendEvent(ctx, &NodeEvent{
		EventIndex: r.eventIndex,
		NodeID:     r.id,
		Timestamp:  now,
		Heartbeat:  nil, // nil heartbeat indicates a shutdown.
	})
}

func (r *Client) sendEvent(ctx context.Context, event *NodeEvent) {
	endpoint, err := r.randomRouterURL(ctx)
	if err != nil {
		slog.InfoContext(ctx, "failed to request random router url", "error", err)
		return
	}

	data, err := event.MarshalBinary()
	if err != nil {
		slog.Error("failed to marshal node event", "error", err)
		return
	}

	slog.InfoContext(ctx, "sending event to router",
		"event_index", event.EventIndex,
		"router_url", endpoint,
		"is_shutdown", event.Heartbeat == nil,
	)

	err = r.doRouterRequest(ctx, http.MethodPost, endpoint, data)
	if err != nil {
		slog.InfoContext(ctx, "failed to send event to router", "error", err, "endpoint", endpoint)
		return
	}
}

func (r *Client) randomRouterURL(ctx context.Context) (string, error) {
	var candidates []string

	if r.routerBaseURL != nil {
		candidates = append(candidates, r.routerBaseURL.String()+"/node-events")
	}

	if r.routerFinder != nil {
		addrs, err := r.routerFinder.FindAddrs(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to find router addresses: %w", err)
		}
		for _, addr := range addrs {
			// TODO: Don't hardcode this port.
			// revive:disable-next-line:unsecure-url-scheme
			candidates = append(candidates, fmt.Sprintf("http://%s:8000/node-events", addr))
		}
	}

	if len(candidates) == 0 {
		return "", errors.New("no candidate URLs found")
	}

	// not an issue, we're not using rand for anything security related
	//nolint:gosec
	i := rand.Intn(len(candidates))
	return candidates[i], nil
}

func (r *Client) doRouterRequest(ctx context.Context, method string, reqURL string, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create router request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	res, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do router request: %w", err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status code: %d", res.StatusCode)
		return httpfmt.ParseBodyAsError(res, err)
	}

	return nil
}

func parseAbsoluteURL(s string) (url.URL, error) {
	result, err := url.Parse(s)
	if err != nil {
		return url.URL{}, err
	}
	if result.Scheme == "" {
		return url.URL{}, fmt.Errorf("wanted absolute url, got %s", s)
	}

	return *result, nil
}
