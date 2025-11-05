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

//go:build otel

package otelutil

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/labstack/echo/v4"
	slogotel "github.com/remychantenay/slog-otel"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
)

// Init initializes the OpenTelemetry pipeline.
// The returned shutdown function should be called to ensure proper cleanup.
func Init(ctx context.Context, serviceName string) (shutdown func(context.Context), err error) {
	// Initialize propagation so traces can span across servers & processes.
	otel.SetTextMapPropagator(propagation.TraceContext{})

	// Initialize an exporter for a generic OTLP endpoint. This will
	// automatically use the URL in the OTEL_EXPORTER_OTLP_ENDPOINT environment
	// variable, if available. Otherwise it will default to "localhost:4318".
	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithInsecure())
	if err != nil {
		return nil, err
	}

	// Initailize tracer provider to use the exporter. The returned
	// shutdown function must be invoked by the caller for cleanup.
	traceProvider := sdktrace.NewTracerProvider(
		// The batch timeout is lowered significantly since tracing will only be
		// used in non-production environments.
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(1*time.Second)),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		)),
	)
	otel.SetTracerProvider(traceProvider)

	Tracer = otel.Tracer("github.com/confidentsecurity/T")

	return func(ctx context.Context) {
		if err := traceProvider.Shutdown(ctx); err != nil {
			slog.ErrorContext(ctx, "failed to shutdown trace provider", slog.Any("error", err))
		}
	}, nil
}

// ServeMuxHandle registers a handle to a serve mux while also wrapping it with
// telemetry. This only works if the path matches the otel name.
func ServeMuxHandle(mux *http.ServeMux, path string, h http.Handler) {
	mux.Handle(path, otelhttp.NewHandler(h, path))
}

// ServeMuxHandleFunc registers a handle function to a serve mux while also
// wrapping it with telemetry. This only works if the path matches the otel name.
func ServeMuxHandleFunc(mux *http.ServeMux, path string, fn func(http.ResponseWriter, *http.Request)) {
	mux.Handle(path, NewHandlerFunc(fn, path))
}

func NewHandlerFunc(fn func(http.ResponseWriter, *http.Request), name string) http.Handler {
	return otelhttp.NewHandler(http.HandlerFunc(fn), name)
}

// NewTransport returns the base round tripper wrapped in an otel transport.
func NewTransport(base http.RoundTripper) http.RoundTripper {
	return otelhttp.NewTransport(base)
}

func NewSlogHandler(handler slog.Handler) slog.Handler {
	return slogotel.OtelHandler{Next: handler}
}

func NewPGXTracer() *otelpgx.Tracer {
	return otelpgx.NewTracer()
}

func NewEchoMiddleware(service string) echo.MiddlewareFunc {
	return otelecho.Middleware(service,
		otelecho.WithSkipper(func(c echo.Context) bool {
			return strings.HasPrefix(c.Request().URL.Path, "/assets")
		}),
	)
}
