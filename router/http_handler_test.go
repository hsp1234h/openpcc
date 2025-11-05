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

package router_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/openpcc/openpcc/ahttp"
	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
	pb "github.com/openpcc/openpcc/gen/protos/router"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/router"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/router/api"
	"github.com/openpcc/openpcc/tags"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRouterReadiness(t *testing.T) {
	t.Run("ok, ready", func(t *testing.T) {

	})

	t.Run("fail, not ready", func(t *testing.T) {

	})
}

func TestRouterHandleNodeEvent(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		t.Parallel()

		handler, rtr := newHandler(t)

		ev := newNodeEvent(t, test.DeterministicV7UUID(0), "http://127.0.0.1")
		// verify we can't query the manifest
		got := rtr.QueryComputeManifests(t.Context(), &api.ComputeManifestRequest{
			Tags:  ev.Heartbeat.RoutingInfo.Tags,
			Limit: 10,
		})
		require.Empty(t, got)

		data := test.RequireProtoMarshal(t, ev.MarshalProto())
		req := httptest.NewRequest(http.MethodPost, "/node-events", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/octet-stream")

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusOK, res.StatusCode)

		// verify we can now query the manifest
		got = rtr.QueryComputeManifests(t.Context(), &api.ComputeManifestRequest{
			Tags:  ev.Heartbeat.RoutingInfo.Tags,
			Limit: 10,
		})
		require.Len(t, got, 1)
	})

	t.Run("fail, invalid body", func(t *testing.T) {
		t.Parallel()

		ev := newNodeEvent(t, test.DeterministicV7UUID(0), "http://127.0.0.1")
		handler, rtr := newHandler(t)

		nepb := ev.MarshalProto()
		nepb.ClearTimestamp() // needs a timestamp

		data := test.RequireProtoMarshal(t, nepb)
		req := httptest.NewRequest(http.MethodPost, "/node-events", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/octet-stream")

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)

		// verify we can't query the manifest
		got := rtr.QueryComputeManifests(t.Context(), &api.ComputeManifestRequest{
			Tags:  ev.Heartbeat.RoutingInfo.Tags,
			Limit: 10,
		})
		require.Empty(t, got)
	})
}

func TestRouterComputeManifestsHTTPHandler(t *testing.T) {
	t.Run("ok, no matching nodes in routing set", func(t *testing.T) {
		t.Parallel()

		handler, _ := newHandler(t)

		manifestReq := &pb.ComputeManifestRequest{}
		manifestReq.SetLimit(10)
		data := test.RequireProtoMarshal(t, manifestReq)

		req := httptest.NewRequest(http.MethodPost, "/compute-manifests", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/octet-stream")
		addCreditHeader(t, req, ahttp.AttestationCurrencyValue)

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusOK, res.StatusCode)

		got := &pb.ComputeManifestList{}
		test.RequireProtoUnmarshalReader(t, res.Body, got)
		items := got.GetItems()
		require.Len(t, items, 0)
	})

	t.Run("ok, matching node in routing set", func(t *testing.T) {
		t.Parallel()

		ev := newNodeEvent(t, test.DeterministicV7UUID(0), "http://127.0.0.1")
		handler, _ := newHandler(t, ev)

		manifestReq := &pb.ComputeManifestRequest{}
		manifestReq.SetLimit(10)
		manifestReq.SetTags(ev.Heartbeat.RoutingInfo.Tags.Slice())
		data := test.RequireProtoMarshal(t, manifestReq)

		req := httptest.NewRequest(http.MethodPost, "/compute-manifests", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/octet-stream")
		addCreditHeader(t, req, ahttp.AttestationCurrencyValue)

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusOK, res.StatusCode)

		gotPB := &pb.ComputeManifestList{}
		test.RequireProtoUnmarshalReader(t, res.Body, gotPB)

		want := api.ComputeManifestList{
			{
				ID: test.DeterministicV7UUID(0),
				Tags: tags.Tags{
					"v1.0.0":            {},
					"model=llama3.2:1b": {},
				},
				Evidence: newEvidenceList(test.DeterministicV7UUID(0)),
			},
		}

		got := api.ComputeManifestList{}
		err := got.UnmarshalProto(gotPB)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("fail, invalid request body", func(t *testing.T) {
		t.Parallel()

		handler, _ := newHandler(t)

		manifestReq := &pb.ComputeManifestRequest{}
		manifestReq.SetLimit(api.MaxComputeManifests + 1) // over max limit
		data := test.RequireProtoMarshal(t, manifestReq)

		req := httptest.NewRequest(http.MethodPost, "/compute-manifests", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/octet-stream")
		addCreditHeader(t, req, ahttp.AttestationCurrencyValue)

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("fail, missing credit", func(t *testing.T) {
		t.Parallel()

		ev := newNodeEvent(t, test.DeterministicV7UUID(0), "http://127.0.0.1")
		handler, _ := newHandler(t, ev)

		manifestReq := &pb.ComputeManifestRequest{}
		manifestReq.SetLimit(10)
		manifestReq.SetTags(ev.Heartbeat.RoutingInfo.Tags.Slice())
		data := test.RequireProtoMarshal(t, manifestReq)

		req := httptest.NewRequest(http.MethodPost, "/compute-manifests", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/octet-stream")
		// missing credit header

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("fail, invalid credit", func(t *testing.T) {
		t.Parallel()

		ev := newNodeEvent(t, test.DeterministicV7UUID(0), "http://127.0.0.1")
		handler, _ := newHandler(t, ev)

		manifestReq := &pb.ComputeManifestRequest{}
		manifestReq.SetLimit(10)
		manifestReq.SetTags(ev.Heartbeat.RoutingInfo.Tags.Slice())
		data := test.RequireProtoMarshal(t, manifestReq)

		req := httptest.NewRequest(http.MethodPost, "/compute-manifests", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/octet-stream")
		addCreditHeader(t, req, currency.Zero) // should be anonpay.AttestationRequestValue

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
}

func TestRouterProxyHTTPHandler(t *testing.T) {
	const (
		clientBody = "hello from client"
		nodePath   = "/target-endpoint" // as defined by the node in runNodeWhile
		nodeBody   = "hello from node"
		nodeStatus = http.StatusOK
	)

	newRoutingInfoHeaderValue := func(t *testing.T, nodeIDs ...uuid.UUID) string {
		info := api.ComputeRequestInfo{
			Candidates: make([]api.ComputeCandidate, 0, len(nodeIDs)),
		}
		for _, nodeID := range nodeIDs {
			info.Candidates = append(info.Candidates, api.ComputeCandidate{
				ID: nodeID,
				// these keys are a concern between the client and the compute node,
				// in these tests we just check if they're forwarded correctly so we use prefixed IDs
				// instead of actual keys.
				EncapsulatedKey: append([]byte("key"), nodeID[:]...),
			})
		}

		txt, err := info.MarshalText()
		require.NoError(t, err)
		return string(txt)
	}

	nodeEncapsulatedKeyHeaderVal := func(nodeID uuid.UUID) string {
		return base64.StdEncoding.EncodeToString(append([]byte("key"), nodeID[:]...))
	}

	t.Run("ok, request with single candidate", func(t *testing.T) {
		t.Parallel()

		nodeID := uuidv7.MustNew()
		ev := runNodeWhile(t, nodeID, func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, nodePath, r.URL.Path)
			test.RequireReadAll(t, []byte(clientBody), r.Body)

			wantHeader := http.Header{}
			wantHeader.Set("Content-Length", "17")
			wantHeader.Set("X-Custom", "hello world!")
			wantHeader.Set(ahttp.NodeCreditAmountHeader, "0")
			wantHeader.Set(api.EncapsulatedKeyHeader, nodeEncapsulatedKeyHeaderVal(nodeID))

			require.Equal(t, wantHeader, r.Header)

			w.WriteHeader(nodeStatus)
			w.Write([]byte(nodeBody))
		})

		handler, _ := newHandler(t, ev)

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(clientBody)))
		req.Header.Set(api.RoutingInfoHeader, newRoutingInfoHeaderValue(t, ev.NodeID))
		req.Header.Set("X-Custom", "hello world!")
		addCreditHeader(t, req, currency.Zero)

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, nodeStatus, res.StatusCode)
		test.RequireReadAll(t, []byte(nodeBody), res.Body)

		require.Equal(t, "", res.Header.Get("X-Test-Refund-Amount"))
		require.Equal(t, nodeID.String(), res.Header.Get(api.NodeIDHeader))
	})

	t.Run("ok, request with single candidate, node gives a refund", func(t *testing.T) {
		t.Parallel()

		nodeID := uuidv7.MustNew()
		ev := runNodeWhile(t, nodeID, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Trailer", ahttp.NodeRefundAmountHeader)

			pb, err := currency.Zero.MarshalProto()
			require.NoError(t, err)
			refundB, err := proto.Marshal(pb)
			require.NoError(t, err)
			val := base64.StdEncoding.EncodeToString(refundB)
			w.Header().Set(ahttp.NodeRefundAmountHeader, val)

			w.WriteHeader(nodeStatus)
			w.Write([]byte(nodeBody))
		})

		handler, _ := newHandler(t, ev)

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(clientBody)))
		req.Header.Set(api.RoutingInfoHeader, newRoutingInfoHeaderValue(t, ev.NodeID))
		addCreditHeader(t, req, currency.Zero)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, nodeStatus, res.StatusCode)
		test.RequireReadAll(t, []byte(nodeBody), res.Body)

		require.Equal(t, nodeID.String(), res.Header.Get(api.NodeIDHeader))
		verifyRefundTrailer(t, res.Trailer.Get(api.RefundHeader), 0)
	})

	t.Run("ok, request with multiple candidates", func(t *testing.T) {
		t.Parallel()

		nodeIDs := []uuid.UUID{}
		evs := []*agent.NodeEvent{}
		for range 5 {
			nodeID := uuidv7.MustNew()
			ev := runNodeWhile(t, nodeID, func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, nodePath, r.URL.Path)
				test.RequireReadAll(t, []byte(clientBody), r.Body)

				require.Equal(t, nodeEncapsulatedKeyHeaderVal(nodeID), r.Header.Get(api.EncapsulatedKeyHeader))

				w.WriteHeader(nodeStatus)
				// node writes its own id to the response body.
				w.Write([]byte(nodeID.String()))
			})
			nodeIDs = append(nodeIDs, nodeID)
			evs = append(evs, ev)
		}

		handler, _ := newHandler(t, evs...)

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(clientBody)))
		req.Header.Set(api.RoutingInfoHeader, newRoutingInfoHeaderValue(t, nodeIDs...))
		addCreditHeader(t, req, currency.Zero)

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, nodeStatus, res.StatusCode)

		data, err := io.ReadAll(res.Body) // body from compute node contains its ID.
		require.NoError(t, err)

		headerID, err := uuidv7.Parse(res.Header.Get(api.NodeIDHeader))
		require.NoError(t, err)

		// verify this was actually one of the nodes.
		require.Contains(t, nodeIDs, headerID)

		// verify the written body matches the header added by the router.
		bodyID, err := uuidv7.Parse(string(data))
		require.NoError(t, err)

		require.Equal(t, headerID, bodyID)
	})

	t.Run("fail, invalid routing info", func(t *testing.T) {
		t.Parallel()

		handler, _ := newHandler(t)

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(clientBody)))
		req.Header.Set(api.RoutingInfoHeader, "bad data")
		addCreditHeader(t, req, currency.Zero)

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("fail, route to node that's not in the routing set", func(t *testing.T) {
		t.Parallel()

		handler, _ := newHandler(t)

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(clientBody)))
		req.Header.Set(api.RoutingInfoHeader, newRoutingInfoHeaderValue(t, uuidv7.MustNew()))
		addCreditHeader(t, req, currency.Zero)

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusNotFound, res.StatusCode)
	})

	t.Run("fail, route to shutdown node", func(t *testing.T) {
		t.Parallel()

		ev1 := newNodeEvent(t, test.DeterministicV7UUID(0), "http://127.0.0.1")
		ev2 := &agent.NodeEvent{
			EventIndex: ev1.EventIndex + 1,
			NodeID:     ev1.NodeID,
			Timestamp:  ev1.Timestamp.Add(time.Millisecond),
			// no heartbeat indicates shutdown.
		}

		handler, _ := newHandler(t, ev1, ev2)

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(clientBody)))
		req.Header.Set(api.RoutingInfoHeader, newRoutingInfoHeaderValue(t, ev1.NodeID))
		addCreditHeader(t, req, currency.Zero)

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusNotFound, res.StatusCode)
	})

	t.Run("fail, missing credit", func(t *testing.T) {
		t.Parallel()

		ev := newNodeEvent(t, test.DeterministicV7UUID(0), "http://127.0.0.1")
		handler, _ := newHandler(t, ev)

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(clientBody)))
		req.Header.Set(api.RoutingInfoHeader, newRoutingInfoHeaderValue(t, ev.NodeID))

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("fail, invalid credit", func(t *testing.T) {
		t.Parallel()

		ev := newNodeEvent(t, test.DeterministicV7UUID(0), "http://127.0.0.1")
		handler, _ := newHandler(t, ev)

		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(clientBody)))
		req.Header.Set(api.RoutingInfoHeader, newRoutingInfoHeaderValue(t, ev.NodeID))
		addCreditHeader(t, req, ahttp.AttestationCurrencyValue)

		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		res := rr.Result()
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
}

func runNodeWhile(t *testing.T, id uuid.UUID, handler http.HandlerFunc) *agent.NodeEvent {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(func() {
		server.Close()
	})

	return newNodeEvent(t, id, server.URL)
}

func newHandler(t *testing.T, nodeEvents ...*agent.NodeEvent) (http.Handler, *router.Router) {
	rtr := router.New(uuidv7.MustNew(), &relaxedNodeEvaluator{})
	for _, nodeEvent := range nodeEvents {
		rtr.AddNodeEvent(t.Context(), nodeEvent)
	}

	handler, err := router.NewHTTPHandler(rtr, newPaymentProcessor())
	require.NoError(t, err)
	return handler, rtr
}

func newPaymentProcessor() *anonpay.Processor {
	return anonpay.NewProcessor(anonpaytest.MustNewIssuer(), test.NewNoopNonceLocker())
}

func addCreditHeader(t *testing.T, r *http.Request, value currency.Value) {
	t.Helper()

	cred := anonpaytest.MustBlindCredit(t.Context(), value)
	txt, err := cred.MarshalText()
	require.NoError(t, err)
	r.Header.Set(api.CreditHeader, string(txt))
}

func verifyRefundTrailer(t *testing.T, refund string, wantAmount int64) {
	t.Helper()

	cred := &anonpay.BlindedCredit{}
	err := cred.UnmarshalText([]byte(refund))
	require.NoError(t, err)

	payee := anonpaytest.MustNewPayee()
	err = payee.VerifyCredit(t.Context(), cred)
	require.NoError(t, err)

	amount, err := cred.Value().Amount()
	require.NoError(t, err)
	require.Equal(t, amount, wantAmount)
}
