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

package openpcc_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openpcc/openpcc"
	"github.com/stretchr/testify/require"
)

func TestRequestParamsFromHeader(t *testing.T) {
	okTests := map[string]struct {
		header   http.Header
		wantFunc func(*openpcc.RequestParams)
	}{
		"ok, default params": {
			header:   http.Header{},
			wantFunc: func(p *openpcc.RequestParams) {},
		},
		"ok, min limit": {
			header: http.Header{
				openpcc.CreditAmountHeader: []string{"0"},
			},
			wantFunc: func(p *openpcc.RequestParams) {
				p.CreditAmount = 0
			},
		},
		"ok, min limit with deprecated header": {
			header: http.Header{
				openpcc.DeprecatedCreditLimitHeader: []string{"42"},
			},
			wantFunc: func(p *openpcc.RequestParams) {
				p.CreditAmount = 42
			},
		},
		"ok, new header takes precedence over deprecated": {
			header: http.Header{
				openpcc.CreditAmountHeader:          []string{"100"},
				openpcc.DeprecatedCreditLimitHeader: []string{"50"},
			},
			wantFunc: func(p *openpcc.RequestParams) {
				p.CreditAmount = 100
			},
		},
		"ok, empty tag header": {
			header: http.Header{
				openpcc.NodeTagsHeader: []string{""},
			},
			wantFunc: func(p *openpcc.RequestParams) {
				p.NodeTags = []string{}
			},
		},
		"ok, empty tag header, only comma": {
			header: http.Header{
				openpcc.NodeTagsHeader: []string{","},
			},
			wantFunc: func(p *openpcc.RequestParams) {
				p.NodeTags = []string{}
			},
		},
		"ok, empty tag header, only commas and whitespace": {
			header: http.Header{
				openpcc.NodeTagsHeader: []string{", 	, , ,, "},
			},
			wantFunc: func(p *openpcc.RequestParams) {
				p.NodeTags = []string{}
			},
		},
		"ok, non-default tags": {
			header: http.Header{
				openpcc.NodeTagsHeader: []string{"weather,v1.0"},
			},
			wantFunc: func(p *openpcc.RequestParams) {
				p.NodeTags = []string{"weather", "v1.0"}
			},
		},
		"ok, surrounding whitespace in tags is trimmed": {
			header: http.Header{
				openpcc.NodeTagsHeader: []string{" llm , v1.0, prem ium	"},
			},
			wantFunc: func(p *openpcc.RequestParams) {
				// 'prem ium' won't be a valid tag, but not a concern at this stage.
				p.NodeTags = []string{"llm", "v1.0", "prem ium"}
			},
		},
		"ok, deprecated node tags header": {
			header: http.Header{
				openpcc.DeprecatedNodeTagsHeader: []string{"gpu,v2.0"},
			},
			wantFunc: func(p *openpcc.RequestParams) {
				p.NodeTags = []string{"gpu", "v2.0"}
			},
		},
		"ok, new node tags header takes precedence over deprecated": {
			header: http.Header{
				openpcc.NodeTagsHeader:           []string{"new,tags"},
				openpcc.DeprecatedNodeTagsHeader: []string{"old,tags"},
			},
			wantFunc: func(p *openpcc.RequestParams) {
				p.NodeTags = []string{"new", "tags"}
			},
		},
		"ok, additional node tag strings ignored (proper header.Get behavior)": {
			header: http.Header{
				openpcc.NodeTagsHeader: []string{"new,tags", "more,tags"},
			},
			wantFunc: func(p *openpcc.RequestParams) {
				p.NodeTags = []string{"new", "tags"}
			},
		},
	}

	for name, tc := range okTests {
		t.Run(name, func(t *testing.T) {
			want := openpcc.DefaultRequestParams()
			tc.wantFunc(&want)

			req := httptest.NewRequest(http.MethodPost, "http://example.com", nil)
			req.Header = tc.header

			got, err := openpcc.RequestParamsFromConfSecHeaders(req, openpcc.DefaultRequestParams())
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}

	failTests := map[string]http.Header{
		"fail, limit not an integer": {
			openpcc.CreditAmountHeader: []string{"test"},
		},
		"fail, deprecated limit not an integer": {
			openpcc.DeprecatedCreditLimitHeader: []string{"test"},
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://example.com", nil)
			req.Header = tc

			_, err := openpcc.RequestParamsFromConfSecHeaders(req, openpcc.DefaultRequestParams())
			require.Error(t, err)
		})
	}
}
