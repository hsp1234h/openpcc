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

package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/noncelocking"
	noncelockinghttp "github.com/openpcc/openpcc/anonpay/noncelocking/httpapi"
	"github.com/openpcc/openpcc/app"
	"github.com/openpcc/openpcc/app/httpapp"
	"github.com/openpcc/openpcc/internal/keys"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/router"
	"github.com/openpcc/openpcc/router/health"
	"github.com/openpcc/openpcc/uuidv7"
)

type AnonpayConfig struct {
	// CreditholeURL is the URL for our CreditHole server
	CreditholeURL string `yaml:"credithole_url"`
	// CurrencyKey is a base64 pem encoded private key used for minting new currency
	CurrencyKey string `yaml:"currency_key"`
}

type Config struct {
	// HTTP is HTTP serving config
	HTTP *httpapp.Config `yaml:"http"`
	// Anonpay configured anonymous payments related services.
	Anonpay AnonpayConfig `yaml:"anonpay"`
	// Healthchecker is config for checking on the health of compute nodes
	Healthchecker *health.CheckerConfig `yaml:"healthchecker"`
	// HealthGrader is config for interpreting a history of health checks
	HealthGrader *health.GraderConfig `yaml:"healthgrader"`
	// How often to re-evaluate and clean up old data.
	CleanupInterval time.Duration `yaml:"cleanup_interval"`
}

const serviceName = "memrouter"

func main() {
	code := run(context.Background())
	os.Exit(code)
}

func run(ctx context.Context) int {

	shutdown, err := otelutil.Init(context.Background(), serviceName)
	if err != nil {
		slog.Error("failed to init opentelemetry", "error", err)
		return 1
	}
	defer shutdown(context.Background())

	derBytes := x509.MarshalPKCS1PrivateKey(anonpaytest.CurrencyKey())

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derBytes,
	}

	// start with default config and override by loading from
	// YAML file and/or environment.
	httpConfig := httpapp.DefaultStreamingConfig()
	httpConfig.Port = "3400"
	cfg := &Config{
		HTTP:            httpConfig,
		Healthchecker:   health.DefaultCheckerConfig(),
		HealthGrader:    health.DefaultGraderConfig(),
		CleanupInterval: time.Second * 30,
		Anonpay: AnonpayConfig{
			CreditholeURL: "http://localhost:3600",
			CurrencyKey:   base64.StdEncoding.EncodeToString(pem.EncodeToMemory(pemBlock)),
		},
	}

	// setup a health grader to evaluate nodes with.
	grader, err := health.NewGrader(cfg.HealthGrader)
	if err != nil {
		slog.Error("failed to create health grader", "error", err)
		return 1
	}

	// create a router.
	rtrID, err := uuidv7.New()
	if err != nil {
		slog.Error("failed to generate id for router", "error", err)
		return 1
	}

	rtr := router.New(rtrID, router.GradedNodeEvaluator(grader, cfg.CleanupInterval))

	currencyPrivateKey, err := keys.ParseX509PKCS1PrivateKeyFromBase64PEM(cfg.Anonpay.CurrencyKey)
	if err != nil {
		slog.Error("failed to parse currency key", "error", err)
		return 1
	}

	issuer, err := anonpay.NewIssuer(currencyPrivateKey)
	if err != nil {
		slog.Error("failed to create anonpay issuer", "error", err)
		return 1
	}

	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: otelutil.NewTransport(http.DefaultTransport),
	}

	creditholeClient := noncelockinghttp.NewClient(httpClient, cfg.Anonpay.CreditholeURL)
	noncelocker := noncelocking.FromTicketLocker(creditholeClient)

	transactor := anonpay.NewProcessor(issuer, noncelocker)
	httpHandler, err := router.NewHTTPHandler(rtr, transactor)
	if err != nil {
		slog.Error("failed to create router http handler", "error", err)
		return 1
	}

	// compose the apps together to run a healthchecking, http serving, cluster member.
	a := app.NewMulti(httpapp.New(cfg.HTTP, httpHandler))

	// run the app until it exits or signals received
	ctx, _ = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)

	code := app.Run(ctx, a, func() (context.Context, context.CancelFunc) {
		// signals received during graceful shutdown cause immediate exit
		return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	})

	return code
}
