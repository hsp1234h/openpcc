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

//go:build !otel

package otelutil

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/exaring/otelpgx"
	"github.com/labstack/echo/v4"
)

func Init(_ context.Context, _ string) (shutdown func(context.Context), err error) {
	return func(_ context.Context) {}, nil
}

func ServeMuxHandle(mux *http.ServeMux, path string, h http.Handler) {
	mux.Handle(path, h)
}

func ServeMuxHandleFunc(mux *http.ServeMux, path string, fn func(http.ResponseWriter, *http.Request)) {
	mux.Handle(path, http.HandlerFunc(fn))
}

func NewHandlerFunc(fn func(http.ResponseWriter, *http.Request), _ string) http.Handler {
	return http.HandlerFunc(fn)
}

func NewTransport(base http.RoundTripper) http.RoundTripper {
	return base
}

func NewSlogHandler(handler slog.Handler) slog.Handler {
	return handler
}

func NewPGXTracer() *otelpgx.Tracer {
	return nil
}

func NewEchoMiddleware(_ string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return next
	}
}
