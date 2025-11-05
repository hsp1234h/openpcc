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
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/openpcc/openpcc/anonpay/noncelocking/httpapi"
	"github.com/openpcc/openpcc/anonpay/noncelocking/inmem"
	"github.com/openpcc/openpcc/app"
	"github.com/openpcc/openpcc/app/config"
	"github.com/openpcc/openpcc/app/httpapp"
	"github.com/openpcc/openpcc/otel/otelutil"
)

type Config struct {
	// HTTP is http server related config
	HTTP *httpapp.Config `yaml:"http"`
}

const serviceName = "credit_hole"

func main() {
	os.Exit(run())
}

func run() int {
	shutdown, err := otelutil.Init(context.Background(), serviceName)
	if err != nil {
		slog.Error("failed to init opentelemetry", "error", err)
		return 1
	}
	defer shutdown(context.Background())

	ctx := context.Background()

	configFile, err := config.FilenameFromArgs(os.Args[1:])
	if err != nil {
		slog.Warn("failed to determine config file", "error", err)
	}

	// start with default config and override by loading from
	// YAML file and/or environment.
	httpConfig := httpapp.DefaultConfig()
	httpConfig.Port = "3600"
	cfg := &Config{
		HTTP: httpConfig,
	}

	err = config.Load(cfg, configFile, nil)
	if err != nil {
		slog.Warn("failed to load config", "error", err)
	}

	server := httpapi.NewServer(inmem.NewNonceLocker())
	httpApp := httpapp.New(cfg.HTTP, server)

	// run the app until it exits or signals received
	ctx, _ = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	return app.Run(ctx, app.NewMulti(httpApp), func() (context.Context, context.CancelFunc) {
		// signals received during graceful shutdown cause immediate exit
		return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	})
}
