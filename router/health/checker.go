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

package health

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/openpcc/openpcc/httpfmt"
	"github.com/openpcc/openpcc/otel/otelutil"
)

// maxErrorBodyLength is the maximum number of bytes that the checker will read from a healthcheck request body.
//
// This limit is in place for two reasons:
//   - To prevent memory exhaustion of the router if a malicious or malfunctioning compute node sends extremely large responses.
//   - To limit the size of error messages in healthchecks. Healthchecks are synced via gossip, which is primarily meant for smaller messages.
//
// 1024 was chosen as an initial guess. We should finetune this if required.
const maxErrorBodyLength = 1024

type CheckerConfig struct {
	// Interval determines how much time there is between healthchecks.
	Interval time.Duration `yaml:"interval"`
	// RequestTimeout is the amount of time to wait for a check to complete
	RequestTimeout time.Duration `yaml:"request_timeout"`
	// Retries is the number of requests made before a healthcheck is considered a failure.
	Retries int `yaml:"retries"`
	// MaxAge determines after which age old local healthchecks are deleted.
	MaxAge time.Duration `yaml:"max_age"`
}

func DefaultCheckerConfig() *CheckerConfig {
	return &CheckerConfig{
		Interval:       30 * time.Second,
		RequestTimeout: 5 * time.Second,
		Retries:        3,
		MaxAge:         15 * time.Minute,
	}
}

type Store interface {
	QueryHealthcheckTargets(ctx context.Context) (map[uuid.UUID]url.URL, int)
	AddHealthcheck(ctx context.Context, c Check)
}

// Checker is an application that runs healthchecks periodically.
type Checker struct {
	timeBetween time.Duration
	retries     int
	httpClient  *http.Client
	maxAge      time.Duration
	store       Store
	ctx         context.Context
	cancel      context.CancelFunc
}

func NewChecker(ctx context.Context, cfg *CheckerConfig, s Store) *Checker {
	retries := 1
	if cfg.Retries > 0 {
		retries = cfg.Retries
	}

	localCtx, cancel := context.WithCancel(ctx)
	return &Checker{
		timeBetween: cfg.Interval,
		retries:     retries,
		httpClient: &http.Client{
			Timeout:   cfg.RequestTimeout,
			Transport: otelutil.NewTransport(http.DefaultTransport),
		},
		maxAge: cfg.MaxAge,
		store:  s,
		ctx:    localCtx,
		cancel: cancel,
	}
}

func (c *Checker) Run() error {
	ticker := time.NewTicker(c.timeBetween)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return nil
		case <-ticker.C:
			c.runHealthChecks(c.ctx)
		}
	}
}

func (c *Checker) runHealthChecks(ctx context.Context) {
	ctx, span := otelutil.Tracer.Start(ctx, "health.Checker.Run")
	defer span.End()

	// run healthchecks
	var wg sync.WaitGroup
	targets, nodeCount := c.store.QueryHealthcheckTargets(ctx)
	slog.Info("running healthchecks", "checked_nodes", len(targets), "total_nodes", nodeCount)

	for nodeID, tgtURL := range targets {
		wg.Go(func() {
			hc, err := c.CheckHealth(ctx, nodeID, tgtURL)
			if err != nil {
				slog.Error("failed to do healthcheck", "error", err, "node_id", nodeID, "url", tgtURL)
				return
			}

			c.store.AddHealthcheck(ctx, hc)
		})
	}
	wg.Wait()
}

func (c *Checker) CheckHealth(ctx context.Context, nodeID uuid.UUID, tgtURL url.URL) (Check, error) {
	hc := Check{
		NodeID: nodeID,
		URL:    tgtURL,
	}

	for i := 0; i < c.retries; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, tgtURL.String(), nil)
		if err != nil {
			return Check{}, fmt.Errorf("failed to create request: %w", err)
		}

		start := time.Now().UTC()

		// reset fields for this attempt
		hc.Timestamp = time.Now().Round(0) // strip monotonic reading.
		hc.HTTPStatusCode = 0
		hc.Latency = 0

		resp, err := c.httpClient.Do(req)
		if err != nil {
			hc.ErrorMessage = err.Error()
		} else {
			hc.HTTPStatusCode = resp.StatusCode
			hc.ErrorMessage = c.responseToErrorMessage(resp)
		}

		hc.Latency = time.Since(start)

		if hc.IsSuccessful() {
			return hc, nil
		}
	}

	return hc, nil
}

func (*Checker) responseToErrorMessage(resp *http.Response) string {
	defer resp.Body.Close()

	input := io.LimitReader(resp.Body, maxErrorBodyLength)

	switch resp.Header.Get("Content-Type") {
	case "application/json":
		v, err := httpfmt.DecodeJSONErrorAsError(input)
		if err != nil {
			return ""
		}
		return v.Error()
	case "application/octet-stream":
		v, err := httpfmt.DecodeBinaryErrorAsError(input)
		if err != nil {
			return ""
		}
		return v.Error()
	default:
		return ""
	}
}

func (c *Checker) Shutdown(_ context.Context) error {
	c.cancel()
	return nil
}
