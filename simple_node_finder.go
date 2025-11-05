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

package openpcc

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/openpcc/openpcc/ahttp"
	"github.com/openpcc/openpcc/attestation/verify"
	"github.com/openpcc/openpcc/auth/credentialing"
	rtrpb "github.com/openpcc/openpcc/gen/protos/router"
	"github.com/openpcc/openpcc/httpfmt"
	"github.com/openpcc/openpcc/httpretry"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/proton"
	"github.com/openpcc/openpcc/router/api"
	"github.com/openpcc/openpcc/tags"
	"go.opentelemetry.io/otel/codes"
	"google.golang.org/protobuf/proto"
)

// simpleNodeFinder is a node finder that fetches candidates from
// the router and verifies them synchronously.
type simpleNodeFinder struct {
	httpClient    *http.Client
	authClient    AuthClient
	verifier      verify.Verifier
	routerBaseURL string
}

func (f *simpleNodeFinder) FindVerifiedNodes(ctx context.Context, maxNodes int, tagslist tags.Tags) ([]VerifiedNode, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "client.simpleNodeFinder.FindVerifiedNodes")
	defer span.End()

	attestationToken, err := f.authClient.GetAttestationToken(ctx)
	if err != nil {
		return nil, otelutil.Errorf(span, "failed to get authenticate and get attestation token: %w", err)
	}

	query := &rtrpb.ComputeManifestRequest{}
	limit, ok := safeInt32(maxNodes)
	if !ok {
		return nil, otelutil.Error(span, "expected max nodes to be safely convertable to int32")
	}
	query.SetLimit(limit)
	query.SetTags(tagslist.Slice())
	data, err := proto.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal compute manifest query: %w", err)
	}

	routerReq, err := http.NewRequestWithContext(ctx, http.MethodPost, f.routerBaseURL+"/compute-manifests", bytes.NewReader(data))
	if err != nil {
		return nil, otelutil.Errorf(span, "failed to create compute manifest request: %w", err)
	}

	routerReq.Header.Set("Content-Type", "application/octet-stream")

	creditHeader, err := encodeCreditHeader(attestationToken)
	if err != nil {
		return nil, otelutil.Errorf(span, "failed to marshal attestation token: %w", err)
	}

	// Credit (attestation token) for this request
	routerReq.Header.Set(ahttp.CreditHeader, creditHeader)

	routerResp, err := httpretry.Do(f.httpClient, routerReq)
	if err != nil {
		return nil, otelutil.Errorf(span, "failed to make ohttp request: %w", err)
	}
	defer routerResp.Body.Close()

	if routerResp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status code %d", routerResp.StatusCode)
		return nil, otelutil.RecordError(span, httpfmt.ParseBodyAsError(routerResp, err))
	}

	manifestList := &rtrpb.ComputeManifestList{}
	err = proton.NewDecoder(routerResp.Body).Decode(manifestList)
	if err != nil {
		return nil, otelutil.Errorf(span, "failed to decode evidence list: %w", err)
	}

	if len(manifestList.GetItems()) == 0 {
		slog.WarnContext(ctx, "Router replied to /compute-manifests with 0 compute nodes")
	}

	items := manifestList.GetItems()
	nodes := make([]VerifiedNode, 0, len(items))
	for _, item := range items {
		var manifest api.ComputeManifest
		err := manifest.UnmarshalProto(item)
		if err != nil {
			slog.ErrorContext(ctx, "failed to unmarshal compute manifest from router", "node_id", item.GetId(), "error", err)
			continue
		}

		data, err := f.verifier.VerifyComputeNode(ctx, manifest.Evidence)
		if err != nil {
			slog.ErrorContext(ctx, "failed to verify evidence for compute node", "node_id", item.GetId(), "error", err)
			continue
		}

		nodes = append(nodes, VerifiedNode{
			Manifest:    manifest,
			TrustedData: *data,
			VerifiedAt:  time.Now(),
		})
	}

	span.SetStatus(codes.Ok, "")
	return nodes, nil
}

func (*simpleNodeFinder) ListCachedVerifiedNodes() ([]VerifiedNode, error) {
	return nil, nil
}

func (f *simpleNodeFinder) GetBadge(ctx context.Context) (credentialing.Badge, error) {
	return f.authClient.GetBadge(ctx)
}

func (*simpleNodeFinder) Close() error {
	return nil
}

func safeInt32(v int) (int32, bool) {
	if v < math.MinInt32 || v > math.MaxInt32 {
		return 0, false
	}

	return int32(v), true
}
