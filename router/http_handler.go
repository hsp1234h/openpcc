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

package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/openpcc/openpcc/ahttp"
	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/chunk"
	"github.com/openpcc/openpcc/httpfmt"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/router/api"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type NodeService interface {
	AddNodeEvent(ctx context.Context, ev *agent.NodeEvent)
	QueryComputeManifests(ctx context.Context, q *api.ComputeManifestRequest) api.ComputeManifestList
	PickNodeFromCandidates(ctx context.Context, info api.ComputeRequestInfo) (api.ComputeCandidate, url.URL, error)
}

func NewHTTPHandler(svc NodeService, paymentProcessor *anonpay.Processor) (http.Handler, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_health", httpfmt.JSONHealthCheck)
	// used by the client to verify OHTTP is set up.
	otelutil.ServeMuxHandle(mux, "GET /ping", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("pong"))
		if err != nil {
			slog.Error("failed to write response", "error", err)
		}
	}))

	otelutil.ServeMuxHandle(mux, "POST /node-events", httpfmt.BinaryHandlerInputOnly(func(ctx context.Context, ev *agent.NodeEvent) error {
		svc.AddNodeEvent(ctx, ev)
		return nil
	}))

	otelutil.ServeMuxHandle(mux, "POST /compute-manifests", newComputeManifestsHandler(svc, paymentProcessor))
	otelutil.ServeMuxHandle(mux, "POST /{$}", newProxyHandler(svc, paymentProcessor)) // only allow for / exactly.

	return mux, nil
}

func newComputeManifestsHandler(svc NodeService, paymentProcessor *anonpay.Processor) http.Handler {
	queryHandler := httpfmt.BinaryHandler(func(ctx context.Context, in *api.ComputeManifestRequest) (api.ComputeManifestList, error) {
		return svc.QueryComputeManifests(ctx, in), nil
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := otelutil.Tracer.Start(r.Context(), "router.ComputeManifestsHandler")
		defer span.End()

		credit := &anonpay.BlindedCredit{}
		err := credit.UnmarshalText([]byte(r.Header.Get(api.CreditHeader)))
		if err != nil {
			otelutil.RecordError2(span, fmt.Errorf("failed to unmarshal credit from text: %w", err))
			httpfmt.BinaryBadRequest(w, r, fmt.Sprintf("invalid credit in %s header", api.CreditHeader))
			return
		}

		if credit.Value() != ahttp.AttestationCurrencyValue {
			slog.ErrorContext(ctx, "invalid credit value", "credit", credit)
			httpfmt.BinaryBadRequest(w, r, "invalid credit value")
			return
		}

		// begin the transaction
		tx, err := paymentProcessor.BeginTransaction(ctx, credit)
		if err != nil {
			otelutil.RecordError2(span, fmt.Errorf("failed to begin transaction: %w", err))
			httpfmt.BinaryBadRequest(w, r, "unprocessable credit")
			return
		}

		// do the query and write the response.
		queryHandler.ServeHTTP(w, r)

		// always commit the transaction.
		err = tx.Commit()
		if err != nil {
			otelutil.RecordError2(span, fmt.Errorf("failed to commit transaction: %w", err))
		}
	})
}

func newProxyHandler(svc NodeService, paymentProcessor *anonpay.Processor) http.Handler {
	type ctxKey string
	const modifyResponseCtxKey ctxKey = "modifyResponse"
	type modifyResponseInput struct {
		tx           *anonpay.Transaction
		creditAmount int64
		nodeURL      url.URL
		candidate    api.ComputeCandidate
	}

	proxy := &httputil.ReverseProxy{
		FlushInterval: 0,
		// Use chunk-friendly transport.
		Transport: otelutil.NewTransport(chunk.NewHTTPTransport(chunk.DefaultDialTimeout)),
		Rewrite: func(pr *httputil.ProxyRequest) {
			input, ok := pr.In.Context().Value(modifyResponseCtxKey).(modifyResponseInput)
			if !ok {
				panic("missing proxy rewrite input") // developer error if this happens. Input is always set before calling the proxy by this handler.
			}

			ctx, span := otelutil.Tracer.Start(pr.In.Context(), "router.ReverseProxy.Rewrite",
				trace.WithAttributes(
					attribute.Int64("creditAmount", input.creditAmount),
					attribute.String("nodeURL", input.nodeURL.String())))
			defer span.End()
			pr.Out = pr.Out.WithContext(ctx)
			// Compute node does not need the full routing header.
			pr.Out.Header.Del(api.RoutingInfoHeader)
			// Compute node does not need the original credit.
			pr.Out.Header.Del(api.CreditHeader)

			// Set the encryption key headers.
			input.candidate.CopyKeysToHeader(pr.Out.Header)
			// Set the credit amount.
			pr.Out.Header.Set(ahttp.NodeCreditAmountHeader, strconv.FormatInt(input.creditAmount, 10))
			pr.Out.URL = &input.nodeURL
		},
		ModifyResponse: func(res *http.Response) error {
			input, ok := res.Request.Context().Value(modifyResponseCtxKey).(modifyResponseInput)
			if !ok {
				panic("missing proxy rewrite input") // should not happen. input is always set before calling the proxy.
			}
			// Add the identity of the compute node that is handling the request so the client can use
			// the correct decryption context to handle the response.
			res.Header.Set(api.NodeIDHeader, input.candidate.ID.String())

			// We might be adding a refund trailer in the EOF callback.
			res.Header.Set("Trailer", api.RefundHeader)

			// If we don't clear the trailers here, the proxy will forward all trailers
			// it knows about. The trailer will still be available in the EOF callback,
			// as it will be repopulated before it's called.
			res.Trailer.Del(api.RefundAmountHeader)

			// Once the body reaches EOF, we commit the transaction for this roundtrip. If the original
			// response contains a refund we commit with unspend credits.
			res.Body = &readCloserEOFCallback{
				orig: res.Body,
				eofCallback: func() error {
					// refund amount header from the compute worker.
					val := res.Trailer.Get(api.RefundAmountHeader)
					// delete again, otherwise the proxy will add it.
					res.Trailer.Del(api.RefundAmountHeader)
					if val == "" {
						// no refund, commit the transaction without unspend credits.
						err := input.tx.Commit()
						if err != nil {
							return fmt.Errorf("failed to commit transaction: %w", err)
						}
						return nil
					}

					var value currency.Value
					err := value.UnmarshalText([]byte(val))
					if err != nil {
						return fmt.Errorf("failed to unmarshal currency value from header: %w", err)
					}

					refund, err := input.tx.CommitWithUnspend(value)
					if err != nil {
						return fmt.Errorf("failed to commit transaction with unspend credits: %w", err)
					}
					refundTxt, err := refund.MarshalText()
					if err != nil {
						return fmt.Errorf("failed to marshal refund to text: %w", err)
					}
					// now finally set the refund header we do want to provide to the client.
					res.Trailer.Set(api.RefundHeader, string(refundTxt))
					return nil
				},
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.ErrorContext(r.Context(), "proxy error", "error", err, "method", r.Method, "path", r.URL.Path)
			http.Error(w, "Proxy error", http.StatusBadGateway)
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := otelutil.Tracer.Start(r.Context(), "router.RoutingHandler")
		defer span.End()

		// proxy.Rewrite does not allow for erroring, so we do some pre-processing before calling the proxy.
		// we save these values into a context so we can use them later in proxy.Rewrite.
		var info api.ComputeRequestInfo
		err := info.UnmarshalText([]byte(r.Header.Get(api.RoutingInfoHeader)))
		if err != nil {
			slog.ErrorContext(ctx, "failed to parse compute request info", "error", err)
			httpfmt.BinaryBadRequest(w, r, fmt.Sprintf("invalid routing info in %s header", api.RoutingInfoHeader))
			otelutil.RecordError2(span, fmt.Errorf("failed to parse compute request info: %w", err))
			return
		}

		credit := &anonpay.BlindedCredit{}
		err = credit.UnmarshalText([]byte(r.Header.Get(api.CreditHeader)))
		if err != nil {
			otelutil.RecordError2(span, fmt.Errorf("failed to unmarshal credit from text: %w", err))
			httpfmt.BinaryBadRequest(w, r, fmt.Sprintf("invalid credit in %s header", api.CreditHeader))
			return
		}

		amount, err := credit.Value().Amount()
		if err != nil {
			otelutil.RecordError2(span, fmt.Errorf("invalid credit value: %w", err))
			httpfmt.BinaryBadRequest(w, r, "invalid credit value")
			return
		}

		// done in memory, so do this before beginning a transaction, which requires a network request to the credithole.
		candidate, nodeURL, err := svc.PickNodeFromCandidates(ctx, info)
		if err != nil {
			slog.ErrorContext(ctx, "failed to pick candidate to handle the request", "error", err)
			otelutil.RecordError2(span, fmt.Errorf("failed to pick candidate to handle the request: %w", err))
			httpfmt.BinaryError(w, r, "all candidate nodes unavailable", http.StatusNotFound)
			return
		}

		tx, err := paymentProcessor.BeginTransaction(ctx, credit)
		if err != nil {
			otelutil.RecordError2(span, fmt.Errorf("failed to begin transaction: %w", err))
			httpfmt.BinaryBadRequest(w, r, "unprocessable credit")
			return
		}

		slog.Debug("routing request to candidate", "node_id", candidate.ID, "node_url", nodeURL)
		// pass the values so we can use them in rewrite.
		ctx = context.WithValue(tx.Context(), modifyResponseCtxKey, modifyResponseInput{
			tx:           tx,
			creditAmount: amount,
			nodeURL:      nodeURL,
			candidate:    candidate,
		})
		span.SetStatus(codes.Ok, "")

		// now let the proxy handle the rest.
		proxy.ServeHTTP(w, r.WithContext(ctx))

		// safe to rollback even if the proxy already committed.
		err = tx.Rollback()
		if err != nil {
			otelutil.RecordError2(span, fmt.Errorf("failed to roll back transaction: %w", err))
		}
	})
}

type readCloserEOFCallback struct {
	orig        io.ReadCloser
	eofCallback func() error
}

func (r *readCloserEOFCallback) Read(b []byte) (int, error) {
	n, err := r.orig.Read(b)
	if errors.Is(err, io.EOF) {
		callbackErr := r.eofCallback()
		if callbackErr != nil {
			return n, callbackErr
		}
	}
	return n, err
}

func (r *readCloserEOFCallback) Close() error {
	return r.orig.Close()
}
