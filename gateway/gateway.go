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

package gateway

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/confidentsecurity/ohttp"
	obhttp "github.com/confidentsecurity/ohttp/encoding/bhttp"
	"github.com/openpcc/openpcc/chunk"
	"github.com/openpcc/openpcc/httpfmt"
	"github.com/openpcc/openpcc/messages"
	"github.com/openpcc/openpcc/otel/otelutil"
)

type Config struct {
	Keys []Key `yaml:"keys"`
	// BankURL is the URL of the bank service. Used to reject requests to random services
	BankURL string `yaml:"bank_url"`
	// RouterURL is the url of the Router service. Used to reject requests to random services
	RouterURL string `yaml:"router_url"`
}

type Key struct {
	// ID is the ID of the public key used to encrypt OHTTP messages for the gateway
	ID byte `yaml:"id"`
	// Seed is a seed used to generate the public/private keypair used to encrypt messages for the OHTTP gateway
	Seed string `yaml:"seed"`
	// ActiveFrom is the time from which the key is active (valid for use) and will be accepted.
	ActiveFrom time.Time `yaml:"active_from"`
	// ActiveUntil is the time after which the key is no longer active and will be rejected (e.g. key expiration).
	ActiveUntil time.Time `yaml:"active_until"`
}

func DefaultConfig() Config {
	return Config{
		Keys: []Key{
			{
				ID:          0,
				Seed:        "",
				ActiveFrom:  time.Now(),
				ActiveUntil: time.Now().AddDate(1, 0, 0),
			},
		},
		BankURL:   "",
		RouterURL: "",
	}
}

const (
	// ExternalBankHost is the unroutable hostname used by the client to signal a decapsulated
	// request should be forwarded to the bank.
	ExternalBankHost = "confsec-bank.invalid"
	// ExternalRouterHost is the unroutable hostname used by the client to signal a decapsulated
	// request should be forwarded to the router.
	ExternalRouterHost = "confsec-router.invalid"
)

type gateway struct {
	bankURL   *url.URL
	routerURL *url.URL
}

func NewGateway(cfg Config) (http.Handler, error) {
	bankURL, err := url.Parse(cfg.BankURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bank URL: %w", err)
	}

	routerURL, err := url.Parse(cfg.RouterURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse router URL: %w", err)
	}

	g := &gateway{
		bankURL:   bankURL,
		routerURL: routerURL,
	}

	reqDecoder, err := obhttp.NewRequestDecoder(
		obhttp.FixedLengthResponseChunks(),
		obhttp.MaxResponseChunkLen(messages.EncapsulatedChunkLen()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create legacy request decoder: %w", err)
	}

	var keyPairs KeyPairs
	for _, key := range cfg.Keys {
		seed, err := hex.DecodeString(key.Seed)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key seed from hex: %w", err)
		}

		keyPairs = append(keyPairs, generateKeyPair(key.ID, seed, key.ActiveFrom, key.ActiveUntil))
	}

	ohttpGateway, err := ohttp.NewGateway(
		keyPairs,
		ohttp.WithRequestValidator(g),
		ohttp.WithRequestDecoder(reqDecoder),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ohttp gateway: %w", err)
	}

	mux := http.NewServeMux()

	decapHandler := limitEndpointsMiddleware(newProxyHandler(g))
	// the ohttp.Middleware will decapsulate/encapsulate and the proxy handler will
	// forward to the relevant service. Proxy may assume that the URL on the request is valid and
	// points to an allow-listed service.
	//
	// IMPORTANT: Don't change this path without changing the OHTTP relay config. We've configured
	// the prod/staging OHTTP relays to forward to /. Their config is not part of the T
	// repository.
	otelutil.ServeMuxHandle(mux, "POST /", ohttp.Middleware(ohttpGateway, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// shortcircuit for ping requests used during performance testing.
		if r.Header.Get("X-Confsec-Ping") == "gateway" {
			_, err := w.Write([]byte("gateway"))
			if err != nil {
				slog.Error("failed to write ping response", "err", err)
			}
			return
		}

		decapHandler.ServeHTTP(w, r)
	})))

	mux.Handle("GET /_health", http.HandlerFunc(httpfmt.JSONHealthCheck))

	return mux, nil
}

func newProxyHandler(g *gateway) http.Handler {
	return &httputil.ReverseProxy{
		FlushInterval: 0,
		Transport:     otelutil.NewTransport(chunk.NewHTTPTransport(chunk.DefaultDialTimeout)),
		Rewrite: func(pr *httputil.ProxyRequest) {
			ctx, span := otelutil.Tracer.Start(pr.In.Context(), "gateway.ReverseProxy")
			defer span.End()
			pr.Out = pr.Out.WithContext(ctx)

			switch pr.In.Host {
			case ExternalBankHost:
				pr.SetURL(g.bankURL)
			case ExternalRouterHost:
				pr.SetURL(g.routerURL)
			default:
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.ErrorContext(r.Context(), "proxy error", "error", err, "method", r.Method, "path", r.URL.Path)
			http.Error(w, "Proxy error", http.StatusBadGateway)
		},
	}
}

// ValidRequest is called by the OHTTP middleware to validate the request.
func (*gateway) ValidRequest(r *http.Request) error {
	// This does a sanity check
	if r.Host != ExternalBankHost && r.Host != ExternalRouterHost {
		return errors.New("request is not for bank or router")
	}

	// Further validation of allowed endpoints is done by passing the request
	// through the limitEndpointsMiddleware.
	return nil
}

func limitEndpointsMiddleware(next http.Handler) http.Handler {
	mux := http.NewServeMux()
	// allowed
	endpoints := []string{
		// bank endpoints.
		"POST " + ExternalBankHost + "/deposit",
		"POST " + ExternalBankHost + "/exchange",
		"POST " + ExternalBankHost + "/withdraw",
		"POST " + ExternalBankHost + "/withdraw-full",
		"POST " + ExternalBankHost + "/balance",
		// router endpoints.
		"GET " + ExternalRouterHost + "/ping",
		"POST " + ExternalRouterHost + "/compute-manifests",
		"POST " + ExternalRouterHost + "/{$}", // matches path / exactly. Used by the router to redirect to compute nodes.
	}

	for _, endpoint := range endpoints {
		mux.Handle(endpoint, next)
	}

	return mux
}
