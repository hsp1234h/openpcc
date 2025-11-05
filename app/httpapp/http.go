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

package httpapp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
)

type HTTP struct {
	Server *http.Server
}

func New(cfg *Config, handler http.Handler) *HTTP {
	if cfg.RequestLogging {
		handler = LoggingMiddleware(handler)
	}

	return &HTTP{
		Server: &http.Server{
			Addr:              "0.0.0.0:" + cfg.Port,
			Handler:           handler,
			ReadTimeout:       cfg.ReadTimeout,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			WriteTimeout:      cfg.WriteTimeout,
		},
	}
}

func (a *HTTP) Run() error {
	slog.Info("Listening on " + a.Server.Addr)
	err := a.Server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (a *HTTP) Shutdown(ctx context.Context) error {
	return a.Server.Shutdown(ctx)
}

func LoggingMiddleware(h http.Handler) http.Handler {
	return handlers.CustomLoggingHandler(os.Stderr, h, logFormatter)
}

// logFormatter adapts the gorilla logging middleware to use slog logging like the rest of our application.
func logFormatter(_ io.Writer, p handlers.LogFormatterParams) {
	// note: this skips using the writer provided by gorilla, but uses the logging infrastructure set up
	// by the rest of the app instead.
	duration := time.Since(p.TimeStamp)
	slog.Info(
		"request served",
		"request_start", p.TimeStamp,
		// log duration in millisecond scale, but with nanosecond precision.
		"duration_ms", (float64(duration.Nanoseconds()) / 1e6),
		"url", p.URL.String(),
		"status_code", p.StatusCode,
		"response_size", p.Size,
		"referer", p.Request.Referer(),
		"user_agent", p.Request.UserAgent(),
	)
}
