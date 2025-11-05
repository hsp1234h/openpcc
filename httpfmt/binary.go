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

package httpfmt

import (
	"context"
	"encoding"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	pb "github.com/openpcc/openpcc/gen/protos/httpfmt"
	"github.com/openpcc/openpcc/proton"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
)

// WriteBinary is a convenience function that writes a binary response with the given status code.
func WriteBinary(w http.ResponseWriter, r *http.Request, data []byte, code int) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))

	w.WriteHeader(code)
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	_, err := w.Write(data)
	if err != nil {
		slog.ErrorContext(r.Context(), "error writing binary response", "error", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
}

// BinaryError is a convenience function that writes a protobuf error response.
func BinaryError(w http.ResponseWriter, r *http.Request, msg string, code int) {
	// Mark span from calling function as errored.
	span := trace.SpanFromContext(r.Context())
	span.SetStatus(codes.Error, msg)

	body := &pb.Error{}
	body.SetMessage(msg)

	data, err := proto.Marshal(body)
	if err != nil {
		slog.ErrorContext(r.Context(), "error marshalling to httpfmt.Error", "error", err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	WriteBinary(w, r, data, code)
}

// DecodeBinaryError is a convenience function that decodes a binary error.
func DecodeBinaryError(r io.Reader) (*pb.Error, error) {
	tgt := &pb.Error{}
	dec := proton.NewDecoder(r)
	err := dec.Decode(tgt)
	if err != nil {
		return nil, err
	}
	return tgt, nil
}

// DecodeBinaryErrorAsError is a convenience function that decodes a binary error as an error.
func DecodeBinaryErrorAsError(r io.Reader) (error, error) {
	pbErr, err := DecodeBinaryError(r)
	if err != nil {
		return nil, err
	}
	return errors.New(pbErr.GetMessage()), nil
}

// BinaryBadRequest is a convenience function that returns a status 400 response.
func BinaryBadRequest(w http.ResponseWriter, r *http.Request, msg string) {
	BinaryError(w, r, msg, http.StatusBadRequest)
}

// BinaryServerError is a convenience function that returns a status 500 response
// without exposing error information to the client.
func BinaryServerError(w http.ResponseWriter, r *http.Request) {
	BinaryError(w, r, "internal server error", http.StatusInternalServerError)
}

type PtrBinaryUnmarshaler[T any] interface {
	*T
	encoding.BinaryUnmarshaler
}

// BinaryHandler unmarshals a to/from the target types and calls targetFunc.
func BinaryHandler[VReq any, TReq PtrBinaryUnmarshaler[VReq], TRes encoding.BinaryMarshaler](targetFunc func(ctx context.Context, in *VReq) (TRes, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/octet-stream" {
			slog.ErrorContext(r.Context(), "invalid content-type")
			BinaryBadRequest(w, r, "invalid Content-Type, requires 'application/octet-stream'")
			return
		}

		input, err := io.ReadAll(r.Body)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to read body", "error", err)
			BinaryBadRequest(w, r, "failed to read body")
			return
		}

		in := TReq(new(VReq))
		err = in.UnmarshalBinary(input)
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to unmarshal to binary", "error", err)
			BinaryBadRequest(w, r, "invalid binary data")
			return
		}

		out, err := targetFunc(r.Context(), in)
		if err != nil {
			slog.ErrorContext(r.Context(), "target function failed", "error", err)
			var statusCodeErr ErrorWithStatusCode
			if errors.As(err, &statusCodeErr) {
				BinaryError(w, r, statusCodeErr.PublicMessage, statusCodeErr.StatusCode)
				return
			}
			BinaryServerError(w, r)
			return
		}

		resBody, err := out.MarshalBinary()
		if err != nil {
			slog.ErrorContext(r.Context(), "failed to marshal response to binary", "error", err)
			BinaryServerError(w, r)
			return
		}

		WriteBinary(w, r, resBody, http.StatusOK)
	})
}

type none struct{}

func (*none) MarshalBinary() ([]byte, error) {
	return nil, nil
}

func (*none) UnmarshalBinary([]byte) error {
	return nil
}

func BinaryHandlerInputOnly[VReq any, TReq PtrBinaryUnmarshaler[VReq]](targetFunc func(ctx context.Context, in *VReq) error) http.Handler {
	return BinaryHandler[VReq, TReq, *none](func(ctx context.Context, in *VReq) (*none, error) {
		err := targetFunc(ctx, in)
		return &none{}, err
	})
}

func BinaryHandlerOutputOnly[TRes encoding.BinaryMarshaler](targetFunc func(ctx context.Context) (TRes, error)) http.Handler {
	return BinaryHandler(func(ctx context.Context, _ *none) (TRes, error) {
		return targetFunc(ctx)
	})
}
