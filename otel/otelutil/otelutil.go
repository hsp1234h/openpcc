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

package otelutil

import (
	"errors"
	"fmt"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Tracer is the global tracer used by T.
// It is initialized to the actual tracer implementation after calling Init().
var Tracer trace.Tracer = noop.Tracer{}

// RecordError is a helper function to attach an error to a span and return it.
func RecordError(span trace.Span, err error) error {
	span.SetStatus(codes.Error, err.Error())
	span.RecordError(err)
	return err
}

// RecordError2 is a helper function to attach an error to a span but not return it.
// This function exists because the errcheck linter requires that we check returned errors.
func RecordError2(span trace.Span, err error) {
	span.SetStatus(codes.Error, err.Error())
	span.RecordError(err)
}

// Error is a helper function to create an error, attach it to the span, and return the error.
func Error(span trace.Span, message string) error {
	return RecordError(span, errors.New(message))
}

// Errorf is a helper function to create an error, attach it to the span, and return the error.
func Errorf(span trace.Span, format string, a ...any) error {
	return RecordError(span, fmt.Errorf(format, a...))
}
