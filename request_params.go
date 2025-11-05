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
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// RequestParams determine how much a request is allowed to cost, and what
// compute nodes should handle it.
//
// These parameters will be sourced from:
// 1. (Optionally) The request itself, either via the [HeaderRequestParameters] or [WithRequestParamsFunc].
// 2. Client default parameters.
// 3. Global default parameters.
type RequestParams struct {
	// CreditAmount is the credit size that will be sent with the request. Note that the
	// actual spent amount may be less than this amount.
	CreditAmount int64 `yaml:"credit_limit"`
	// NodeTags are used to find compute nodes that are candidates for this request.
	NodeTags []string `yaml:"node_tags"`
}

// DefaultRequestParams returns the globally default request parameters.
func DefaultRequestParams() RequestParams {
	return RequestParams{
		NodeTags: []string{"llm"},
	}
}

// RequestParamsFunc is a function that extract request parameters from a request.
type RequestParamsFunc func(r *http.Request, p RequestParams) (RequestParams, error)

const (
	//nolint:gosec
	CreditAmountHeader = "X-Confsec-Credit-Amount"
	NodeTagsHeader     = "X-Confsec-Node-Tags"
	BadgeHeader        = "X-Confsec-Badge"

	// TODO(CS-958): remove deprecated headers
	// Deprecated: Use CreditAmountHeader instead
	//nolint:gosec
	DeprecatedCreditLimitHeader = "X-Confident-Security-Credit-Limit"
	// Deprecated: Use NodeTagsHeader instead
	//nolint:gosec
	DeprecatedNodeTagsHeader = "X-Confident-Security-Node-Tags"
)

// RequestParamsFromConfSecHeaders extracts request parameters from the confident security
// headers of the given request.
//
// CreditAmount is taken from [CreditAmountHeader] or [DeprecatedCreditLimitHeader].
// NodeTags are intepretested as a comma separated list from [NodeTagsHeader] or [DeprecatedNodeTagsHeader].
func RequestParamsFromConfSecHeaders(r *http.Request, p RequestParams) (RequestParams, error) {
	// Check new header first, then fall back to deprecated header
	limitVal := r.Header.Get(CreditAmountHeader)
	if limitVal == "" {
		limitVal = r.Header.Get(DeprecatedCreditLimitHeader)
	}

	if limitVal != "" {
		limit, err := strconv.ParseInt(limitVal, 10, 64)
		if err != nil {
			return RequestParams{}, fmt.Errorf("failed to parse credit amount header value as an integer: %w", err)
		}

		p.CreditAmount = limit
	}

	// we allow empty sets of tags to route to all potential nodes.
	// need to differentiate between no header and empty header value, so can't use header.Get.
	// Check new header first, then fall back to deprecated header
	tagsVals := r.Header.Values(NodeTagsHeader)
	if len(tagsVals) == 0 {
		tagsVals = r.Header.Values(DeprecatedNodeTagsHeader)
	}

	if len(tagsVals) > 0 {
		p.NodeTags = []string{}

		// only use the first tag, like with header.Get.
		for rawTag := range strings.SplitSeq(tagsVals[0], ",") {
			trimmed := strings.TrimSpace(rawTag)
			if trimmed == "" {
				continue
			}
			p.NodeTags = append(p.NodeTags, trimmed)
		}
	}

	return p, nil
}

type ctxKey int

const (
	refundCallbackCtxKey ctxKey = iota
)

// ContextWithRefundCallback returns a context with the callback added to it. When the resulting context is used
// as a request context, the callback will be invoked for the response refund.
func ContextWithRefundCallback(ctx context.Context, callback func(amount int64)) context.Context {
	return context.WithValue(ctx, refundCallbackCtxKey, callback)
}

func refundCallback(ctx context.Context, amount int64) {
	val := ctx.Value(refundCallbackCtxKey)
	f, ok := val.(func(amount int64))
	if !ok {
		return
	}

	f(amount)
}
