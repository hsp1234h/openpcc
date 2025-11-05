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
	"fmt"
	"sort"
	"time"

	pb "github.com/openpcc/openpcc/gen/protos/router/health"
)

// History contains are the health checks for a single node.
type History []Check

func (h History) MarshalProto() *pb.History {
	hpb := &pb.History{}

	checks := make([]*pb.Check, len(h))

	for i, hc := range h {
		checks[i] = hc.MarshalProto()
	}

	hpb.SetChecks(checks)
	return hpb
}

func (h *History) UnmarshalProto(hpb *pb.History) error {
	checks := hpb.GetChecks()
	newH := make([]Check, len(checks))
	for i, check := range checks {
		err := newH[i].UnmarshalProto(check)
		if err != nil {
			return fmt.Errorf("failed to unmarshal healthcheck %d: %w", i, err)
		}

		if i > 0 {
			if newH[i].NodeID != newH[i-1].NodeID {
				return fmt.Errorf(
					"expected all healthchecks to be for the same node, got ids %s and %s",
					newH[i].NodeID,
					newH[i-1].NodeID,
				)
			}

			if newH[i].Timestamp.Before(newH[i-1].Timestamp) {
				return fmt.Errorf(
					"expected history to be ordered from old to new, timestamp out of order: %s",
					newH[i].Timestamp.Format(time.RFC3339),
				)
			}
		}
	}

	*h = newH

	return nil
}

// Insert inserts a health check into the history and returns the new history.
func (h History) Insert(hc Check) (History, error) {
	if len(h) > 0 && h[0].NodeID != hc.NodeID {
		return nil, fmt.Errorf("mismatched node ID: has %s got %s", h[0].NodeID, hc.NodeID)
	}
	// check for duplicates
	for _, existing := range h {
		if existing.Equal(hc) {
			return h, nil
		}
	}

	// assuming we have a max of ~50 healthchecks here we should be fine just appending
	// and sorting. If we need more healthchecks we might want to revisit this.
	h = append(h, hc)
	sort.Slice(h, func(i, j int) bool {
		return h[i].Timestamp.Before(h[j].Timestamp)
	})

	return h, nil
}

// Merge merges h with the provided history. Merge returns the merged history and an error.
//
// It assumes the provided histories are in chronological order, with the oldest healthchecks first.
// Merge returns an error if provided healthchecks are for different nodes.
func (h History) Merge(other History) (History, error) {
	if len(other) == 0 {
		return h, nil
	}
	if len(h) == 0 {
		return other, nil
	}

	// sanity check
	if h[0].NodeID != other[0].NodeID {
		return nil, fmt.Errorf("histories are for different nodes %v and %v", h[0].NodeID, other[0].NodeID)
	}

	merged := make(History, 0, len(h)+len(other))
	i, j := 0, 0

	for i < len(h) && j < len(other) {
		// check if the healthcheck in h or other comes before the other
		if h[i].Timestamp.Before(other[j].Timestamp) {
			merged = append(merged, h[i])
			i++
			continue
		} else if other[j].Timestamp.Before(h[i].Timestamp) {
			merged = append(merged, other[j])
			j++
			continue
		}

		// same timestamps.

		if h[i].Equal(other[j]) {
			// healthcheck fully equal, take either one.
			merged = append(merged, h[i])
			i++
			j++
			continue
		}

		// take both.
		merged = append(merged, h[i])
		merged = append(merged, other[j])
		i++
		j++
	}

	merged = append(merged, h[i:]...)
	merged = append(merged, other[j:]...)

	return merged, nil
}

// After returns a new History containing only entries with timestamps
// at or after cutoff. The returned History shares the same backing array
// as the original History.
func (h History) After(cutoff time.Time) History {
	if len(h) == 0 {
		return h
	}

	index := sort.Search(len(h), func(i int) bool {
		return !h[i].Timestamp.Before(cutoff)
	})

	// all elements should be removed, return an empty history.
	if index >= len(h) {
		return History{}
	}

	// reslice history
	return h[index:]
}

type HistoryStats struct {
	Total                int
	Successes            int
	CurrentFailureStreak int
}

func (s HistoryStats) SuccessRate() (float64, bool) {
	if s.Total == 0 {
		return 0, false
	}
	return float64(s.Successes) / float64(s.Total), true
}

func (h History) Stats() HistoryStats {
	if len(h) == 0 {
		return HistoryStats{}
	}
	stats := HistoryStats{
		Total: len(h),
	}

	failStreak := true
	for i := len(h) - 1; i >= 0; i-- {
		if h[i].IsSuccessful() {
			stats.Successes++
			failStreak = false
		} else if failStreak {
			stats.CurrentFailureStreak++
		}
	}

	return stats
}
