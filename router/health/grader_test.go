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

package health_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/openpcc/openpcc/router/health"
	"github.com/stretchr/testify/require"
)

func TestNewGrader(t *testing.T) {
	failTests := map[string]func(cfg *health.GraderConfig){
		"fail, zero min checks": func(cfg *health.GraderConfig) {
			cfg.MinChecks = 0
		},
		"fail, negative min checks": func(cfg *health.GraderConfig) {
			cfg.MinChecks = -1
		},
		"fail, unavailable threshold out of lower range": func(cfg *health.GraderConfig) {
			cfg.MinSuccessRate = -0.1
		},
		"fail, unavailable threshold out of upper range": func(cfg *health.GraderConfig) {
			cfg.MinSuccessRate = 1.1
		},
		"fail, negative max failure streak": func(cfg *health.GraderConfig) {
			cfg.MaxRecentFailureStreak = -1
		},
		"fail, zero max age": func(cfg *health.GraderConfig) {
			cfg.MaxAge = 0
		},
		"fail, negative max age": func(cfg *health.GraderConfig) {
			cfg.MaxAge = -time.Millisecond
		},
		"fail, both min success rate and max failure streak disabled": func(cfg *health.GraderConfig) {
			cfg.MinSuccessRate = 0
			cfg.MaxRecentFailureStreak = 0
		},
	}

	for name, modFunc := range failTests {
		t.Run(name, func(t *testing.T) {
			cfg := health.DefaultGraderConfig()
			modFunc(cfg)

			_, err := health.NewGrader(cfg)
			require.Error(t, err)
		})
	}
}

func TestGraderGrade(t *testing.T) {
	now := timestamp(10)

	successRateOnly := func() *health.GraderConfig {
		return &health.GraderConfig{
			MinChecks:              4,
			MinSuccessRate:         0.5,
			MaxRecentFailureStreak: 0,
			MaxAge:                 10 * time.Minute,
		}
	}

	streakOnly := func() *health.GraderConfig {
		return &health.GraderConfig{
			MinChecks:              4,
			MinSuccessRate:         0,
			MaxRecentFailureStreak: 3,
			MaxAge:                 10 * time.Minute,
		}
	}

	both := func() *health.GraderConfig {
		return &health.GraderConfig{
			MinChecks:              4,
			MinSuccessRate:         0.5,
			MaxRecentFailureStreak: 3,
			MaxAge:                 10 * time.Minute,
		}
	}

	failCheck := func(mins int) health.Check {
		c := check(mins)
		c.HTTPStatusCode = http.StatusInternalServerError
		return c
	}

	tests := map[string]struct {
		cfg     *health.GraderConfig
		history health.History
		want    health.Status
	}{
		"unknown, empty history": {
			cfg:     both(),
			history: health.History{},
			want:    health.StatusUnknown,
		},
		"unknown, not enough checks": {
			cfg: both(),
			history: health.History{
				// 3 < 4
				check(0), check(1), check(2),
			},
			want: health.StatusUnknown,
		},
		"unknown, checks too old": {
			cfg: both(),
			history: health.History{
				// enough checks, but too old.
				check(-4), check(-3), check(-2), check(-1),
			},
			want: health.StatusUnknown,
		},
		"ok, min nr of checks": {
			cfg: both(),
			history: health.History{
				// 100% success.
				check(0), check(1), check(2), check(3),
			},
			want: health.StatusOK,
		},
		"ok, failed checks are too old": {
			cfg: both(),
			history: health.History{
				// 100% success, 3 checks too old.
				failCheck(-4), failCheck(-3), failCheck(-2), failCheck(-1), check(0), check(1), check(2), check(3),
			},
			want: health.StatusOK,
		},
		"ok, over min success rate": {
			cfg: both(),
			history: health.History{
				// 75% success, 0 failure streak.
				check(0), check(1), failCheck(2), check(3),
			},
			want: health.StatusOK,
		},
		"ok, on min success rate": {
			cfg: both(),
			history: health.History{
				// 50% success, 0 failure streak.
				check(0), failCheck(1), failCheck(2), check(3),
			},
			want: health.StatusOK,
		},
		"unavailable, under min success rate": {
			cfg: both(),
			history: health.History{
				// 25% success, 0 failure streak.
				failCheck(0), failCheck(1), failCheck(2), check(3),
			},
			want: health.StatusUnavailable,
		},
		"ok, under min success rate, under max failure streak": {
			cfg: both(),
			history: health.History{
				// 60% success, 2 failure streak.
				check(0), check(1), check(2), failCheck(3), failCheck(4),
			},
			want: health.StatusOK,
		},
		"unavailable, over min success rate, on max failure streak": {
			cfg: both(),
			history: health.History{
				// 62.5% success, 3 failure streak.
				check(0), check(1), check(2), check(4), check(5), failCheck(6), failCheck(7), failCheck(8),
			},
			want: health.StatusUnavailable,
		},
		"unavailable, over min success rate, over max failure streak": {
			cfg: both(),
			history: health.History{
				// 60% success, 4 failure streak.
				check(0), check(1), check(2), check(4), check(5), check(6), failCheck(7), failCheck(8), failCheck(9), failCheck(10),
			},
			want: health.StatusUnavailable,
		},
		"ok, over min success rate, failure streak disabled": {
			cfg: successRateOnly(),
			history: health.History{
				// 60% success, 4 failure streak.
				check(0), check(1), check(2), check(4), check(5), check(6), failCheck(7), failCheck(8), failCheck(9), failCheck(10),
			},
			want: health.StatusOK,
		},
		"ok, min success rate disabled, under failure streak": {
			cfg: streakOnly(),
			history: health.History{
				// 10% success, 2 failure streak.
				failCheck(0), failCheck(1), failCheck(2), failCheck(4), failCheck(5), failCheck(6), failCheck(7), check(8), failCheck(9), failCheck(10),
			},
			want: health.StatusOK,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			g, err := health.NewGrader(tc.cfg)
			require.NoError(t, err)
			g.NowFunc = func() time.Time {
				return now
			}

			got := g.Grade(tc.history)
			require.Equal(t, tc.want, got)
		})
	}
}
