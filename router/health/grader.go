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

package health

import (
	"errors"
	"fmt"
	"time"
)

// GraderConfig confiures a health grader
type GraderConfig struct {
	// MinChecks is the minimum number of healthchecks we need in a time window
	// before a status is determined. If this number of checks is not reached, StatusUnknown is returned.
	MinChecks int `yaml:"min_checks"`

	// MinSuccessRate is the success rate below which a node is considered unavailable.
	//
	// Set to zero to only use consecutive failures to determine unavailable status.
	MinSuccessRate float64 `yaml:"min_success_rate"`

	// MaxRecentFailureStreak is the number of consecutive failures after which a node is considered
	// unavailable, regardless of success rate. This allows the grader to prioritize recent failures over overall success rate.
	//
	// The grader counts backward from the most recent healthcheck.
	//
	// Set to zero to disable max consecutive failures.
	MaxRecentFailureStreak int `yaml:"max_recent_failure_streak"`

	// MaxAge is max age of healthchecks considered by the grader. Healthchecks older than this will be skipped.
	MaxAge time.Duration `yaml:"max_age"`
}

func DefaultGraderConfig() *GraderConfig {
	return &GraderConfig{
		MinChecks:              3,
		MinSuccessRate:         0.9,
		MaxRecentFailureStreak: 3,
		MaxAge:                 time.Minute * 15,
	}
}

// Graders determines the status of healthcheck histories.
type Grader struct {
	cfg     *GraderConfig
	NowFunc func() time.Time
}

func NewGrader(cfg *GraderConfig) (*Grader, error) {
	if cfg.MinChecks <= 0 {
		return nil, fmt.Errorf("min checks must be at least 1, got %d", cfg.MinChecks)
	}

	if cfg.MinSuccessRate < 0 || cfg.MinSuccessRate > 1 {
		return nil, fmt.Errorf("unavailable threshold needs to be between 0 and 1, got %v", cfg.MinSuccessRate)
	}

	if cfg.MaxRecentFailureStreak < 0 {
		return nil, fmt.Errorf("max failure streak needs to be at least 0, got %v", cfg.MaxRecentFailureStreak)
	}

	if cfg.MaxAge <= 0 {
		return nil, fmt.Errorf("needs a max age, got %v", cfg.MaxAge)
	}

	if cfg.MaxRecentFailureStreak == 0 && cfg.MinSuccessRate == 0 {
		return nil, errors.New("needs a failure condition, both max failure streak and unavailable threshold are zero")
	}

	return &Grader{
		cfg: cfg,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	}, nil
}

func (g *Grader) Grade(history History) Status {
	cutoff := g.NowFunc().Add(-g.cfg.MaxAge)
	window := history.After(cutoff)
	if len(window) < g.cfg.MinChecks {
		return StatusUnknown
	}

	stats := window.Stats()
	if g.cfg.MaxRecentFailureStreak != 0 && stats.CurrentFailureStreak >= g.cfg.MaxRecentFailureStreak {
		return StatusUnavailable
	}

	if g.cfg.MinSuccessRate != 0 {
		rate, ok := stats.SuccessRate()
		if !ok {
			return StatusUnknown
		}

		if rate < g.cfg.MinSuccessRate {
			return StatusUnavailable
		}
	}

	return StatusOK
}

// MaxAge returns the max age.
func (g *Grader) MaxAge() time.Duration {
	return g.cfg.MaxAge
}
