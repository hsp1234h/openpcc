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
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/openpcc/openpcc/router"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/router/health"
	"github.com/openpcc/openpcc/router/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGradedNodeEvaluator(t *testing.T) {
	grader, err := health.NewGrader(&health.GraderConfig{
		MinChecks:              1,
		MinSuccessRate:         0.5,
		MaxRecentFailureStreak: 2,
		MaxAge:                 time.Hour,
	})
	require.NoError(t, err)

	evaluator := router.GradedNodeEvaluator(grader, time.Minute)

	testUUID, err := uuid.NewRandom()
	require.NoError(t, err)
	testURL, err := url.Parse("http://localhost/test")
	require.NoError(t, err)

	tests := map[string]struct {
		agent         *state.Agent
		nodeHealth    *state.NodeHealth
		wantRouting   bool
		wantEvict     bool
		wantNextCheck bool
	}{
		"no agent with no history": {
			agent:      nil,
			nodeHealth: nil,
			wantEvict:  true,
		},
		"shutdown agent": {
			agent: &state.Agent{
				ShutdownAt: &time.Time{},
			},
			wantEvict: true,
		},
		"timed out agent": {
			agent: &state.Agent{
				LastEventTimestamp: time.Now().Add(-2 * time.Hour),
			},
			wantEvict: true,
		},
		"available agent with healthy history": {
			agent: &state.Agent{
				LastEventTimestamp: time.Now(),
				RoutingInfo: &agent.RoutingInfo{
					URL: *testURL,
				},
			},
			nodeHealth: &state.NodeHealth{
				History: health.History{
					{
						NodeID:         testUUID,
						URL:            *testURL,
						Timestamp:      time.Now(),
						Latency:        time.Second,
						HTTPStatusCode: http.StatusOK,
					},
				},
			},
			wantRouting:   true,
			wantNextCheck: true,
		},
		"available agent with unhealthy history": {
			agent: &state.Agent{
				LastEventTimestamp: time.Now(),
				RoutingInfo: &agent.RoutingInfo{
					URL: *testURL,
				},
			},
			nodeHealth: &state.NodeHealth{
				History: health.History{
					{
						NodeID:         testUUID,
						URL:            *testURL,
						Timestamp:      time.Now(),
						Latency:        time.Second,
						HTTPStatusCode: http.StatusInternalServerError,
					},
				},
			},
			wantRouting: false,
		},
		"nil agent with non-nil history": {
			agent: nil,
			nodeHealth: &state.NodeHealth{
				History: health.History{},
			},
			wantRouting:   false,
			wantNextCheck: true,
		},
		"nil agent with healthy history": {
			agent: nil,
			nodeHealth: &state.NodeHealth{
				History: health.History{
					{
						NodeID:         testUUID,
						URL:            *testURL,
						Timestamp:      time.Now(),
						Latency:        time.Second,
						HTTPStatusCode: http.StatusOK,
					},
					{
						NodeID:         testUUID,
						URL:            *testURL,
						Timestamp:      time.Now().Add(-time.Minute),
						Latency:        time.Second,
						HTTPStatusCode: http.StatusOK,
					},
				},
			},
			wantRouting:   false,
			wantNextCheck: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			routing, nextCheck := evaluator(tc.agent, tc.nodeHealth)

			if tc.wantEvict {
				assert.Nil(t, routing)
				assert.Nil(t, nextCheck)
			} else {
				assert.Equal(t, tc.wantRouting, routing != nil)
				assert.Equal(t, tc.wantNextCheck, nextCheck != nil)
			}
		})
	}
}
