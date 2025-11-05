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
	"net/url"
	"testing"
	"time"

	pb "github.com/openpcc/openpcc/gen/protos/router/health"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/router/health"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistoryMarshalUnmarshalProto(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		check1 := check(0)
		check2 := check(0) // same timestamp as check1
		check3 := check(1)

		pbh := &pb.History{}
		pbh.SetChecks([]*pb.Check{
			check1.MarshalProto(),
			check2.MarshalProto(),
			check3.MarshalProto(),
		})

		got := health.History{}
		err := got.UnmarshalProto(pbh)
		require.NoError(t, err)

		want := health.History{
			check(0),
			check(0),
			check(1),
		}

		require.Equal(t, want, got)

		// check again but with non-hardcoded pb
		pbh = got.MarshalProto()
		err = got.UnmarshalProto(pbh)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("ok, empty history", func(t *testing.T) {
		pbh := &pb.History{}
		got := health.History{}
		err := got.UnmarshalProto(pbh)
		require.NoError(t, err)

		want := health.History{}
		require.Equal(t, want, got)

		// check again but with non-hardcoded pb
		pbh = got.MarshalProto()
		err = got.UnmarshalProto(pbh)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	failTests := map[string]func(*pb.History){
		"fail, different node IDs": func(h *pb.History) {
			check1 := check(0)
			check2 := check(1)
			check2.NodeID = uuidv7.MustNew()
			h.SetChecks([]*pb.Check{
				check1.MarshalProto(),
				check2.MarshalProto(),
			})
		},
		"fail, checks out of order": func(h *pb.History) {
			check1 := check(1)
			check2 := check(0)
			h.SetChecks([]*pb.Check{
				check1.MarshalProto(),
				check2.MarshalProto(),
			})
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			pbh := &pb.History{}

			tc(pbh)

			h := health.History{}
			err := h.UnmarshalProto(pbh)
			require.Error(t, err)
		})
	}
}

func TestHistoryInsert(t *testing.T) {
	tests := map[string]struct {
		initial health.History
		insert  health.Check
		want    health.History
	}{
		"ok, insert to empty": {
			initial: health.History{},
			insert:  check(1),
			want:    health.History{check(1)},
		},
		"ok, insert newer": {
			initial: health.History{check(1)},
			insert:  check(2),
			want:    health.History{check(1), check(2)},
		},
		"ok, insert older": {
			initial: health.History{check(2)},
			insert:  check(1),
			want:    health.History{check(1), check(2)},
		},
		"ok, insert middle": {
			initial: health.History{check(1), check(3)},
			insert:  check(2),
			want:    health.History{check(1), check(2), check(3)},
		},
		"ok, insert duplicate": {
			initial: health.History{check(1), check(2)},
			insert:  check(1),
			want:    health.History{check(1), check(2)},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			original := make(health.History, len(tc.initial))
			copy(original, tc.initial)

			got, err := tc.initial.Insert(tc.insert)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, original, tc.initial, "original slice should be unchanged")
		})
	}

	t.Run("fail, inserting with different node id", func(t *testing.T) {
		h := health.History{check(1)}
		hc := check(2)
		hc.NodeID = uuidv7.MustNew()

		_, err := h.Insert(hc)
		require.Error(t, err)
		require.Equal(t, health.History{check(1)}, h, "original slice should be unchanged")
	})
}

func TestHistoryMerge(t *testing.T) {
	tests := map[string]struct {
		h1   health.History
		h2   health.History
		want health.History
	}{
		"ok, empty histories": {
			h1:   health.History{},
			h2:   health.History{},
			want: health.History{},
		},
		"ok, first history empty": {
			h1:   health.History{},
			h2:   health.History{check(1)},
			want: health.History{check(1)},
		},
		"ok, second history empty": {
			h1:   health.History{check(1)},
			h2:   health.History{},
			want: health.History{check(1)},
		},
		"ok, non-overlapping histories": {
			h1:   health.History{check(1), check(3)},
			h2:   health.History{check(2), check(4)},
			want: health.History{check(1), check(2), check(3), check(4)},
		},
		"ok, overlapping histories": {
			h1:   health.History{check(1), check(2)},
			h2:   health.History{check(2), check(3)},
			want: health.History{check(1), check(2), check(3)},
		},
		"ok, full overlap": {
			h1:   health.History{check(1), check(2)},
			h2:   health.History{check(1), check(2)},
			want: health.History{check(1), check(2)},
		},
		"ok, interleaved timestamps": {
			h1:   health.History{check(1), check(4)},
			h2:   health.History{check(2), check(3)},
			want: health.History{check(1), check(2), check(3), check(4)},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := tc.h1.Merge(tc.h2)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	t.Run("fail, histories for different nodes", func(t *testing.T) {
		h1 := health.History{check(1)}
		h2 := health.History{check(1)}
		h2[0].NodeID = uuidv7.MustNew()

		_, err := h1.Merge(h2)
		require.Error(t, err)
	})
}

func TestHistoryAfter(t *testing.T) {
	tests := map[string]struct {
		initial health.History
		cutoff  time.Time
		want    health.History
	}{
		"empty history": {
			initial: health.History{},
			cutoff:  timestamp(0),
			want:    health.History{},
		},
		"remove none": {
			initial: health.History{check(1), check(2), check(3)},
			cutoff:  timestamp(0),
			want:    health.History{check(1), check(2), check(3)},
		},
		"remove all": {
			initial: health.History{check(1), check(2), check(3)},
			cutoff:  timestamp(4),
			want:    health.History{},
		},
		"remove some": {
			initial: health.History{check(1), check(2), check(4), check(5)},
			cutoff:  timestamp(3),
			want:    health.History{check(4), check(5)},
		},
		"cutoff exactly on timestamp": {
			initial: health.History{check(1), check(2), check(3)},
			cutoff:  timestamp(2),
			want:    health.History{check(2), check(3)},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			original := make(health.History, len(tc.initial))
			copy(original, tc.initial)

			got := tc.initial.After(tc.cutoff)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, original, tc.initial, "original slice should be unchanged")
		})
	}
}

func TestHistoryStats(t *testing.T) {
	tests := map[string]struct {
		history         health.History
		want            health.HistoryStats
		hasSuccessRate  bool
		wantSuccessRate float64
	}{
		"nil history": {
			history: nil,
			want: health.HistoryStats{
				Total:                0,
				Successes:            0,
				CurrentFailureStreak: 0,
			},
			hasSuccessRate:  false,
			wantSuccessRate: 0,
		},
		"empty history": {
			history: health.History{},
			want: health.HistoryStats{
				Total:                0,
				Successes:            0,
				CurrentFailureStreak: 0,
			},
			hasSuccessRate:  false,
			wantSuccessRate: 0,
		},
		"1 successful check": {
			history: health.History{check(0)},
			want: health.HistoryStats{
				Total:                1,
				Successes:            1,
				CurrentFailureStreak: 0,
			},
			hasSuccessRate:  true,
			wantSuccessRate: 1,
		},
		"1 failed check": {
			history: health.History{failCheck(0)},
			want: health.HistoryStats{
				Total:                1,
				Successes:            0,
				CurrentFailureStreak: 1,
			},
			hasSuccessRate:  true,
			wantSuccessRate: 0,
		},
		"2 in 3 successful checks, failure at start": {
			history: health.History{failCheck(0), check(1), check(2)},
			want: health.HistoryStats{
				Total:                3,
				Successes:            2,
				CurrentFailureStreak: 0,
			},
			hasSuccessRate:  true,
			wantSuccessRate: 2.0 / 3.0,
		},
		"2 in 3 successful checks, failure at end": {
			history: health.History{check(0), check(1), failCheck(2)},
			want: health.HistoryStats{
				Total:                3,
				Successes:            2,
				CurrentFailureStreak: 1,
			},
			hasSuccessRate:  true,
			wantSuccessRate: 2.0 / 3.0,
		},
		"1 in 3 successful checks, failure at start": {
			history: health.History{failCheck(0), failCheck(1), check(2)},
			want: health.HistoryStats{
				Total:                3,
				Successes:            1,
				CurrentFailureStreak: 0,
			},
			hasSuccessRate:  true,
			wantSuccessRate: 1.0 / 3.0,
		},
		"1 in 3 successful checks, failure at end": {
			history: health.History{check(0), failCheck(1), failCheck(2)},
			want: health.HistoryStats{
				Total:                3,
				Successes:            1,
				CurrentFailureStreak: 2,
			},
			hasSuccessRate:  true,
			wantSuccessRate: 1.0 / 3.0,
		},
		"all failures": {
			history: health.History{failCheck(0), failCheck(1), failCheck(2)},
			want: health.HistoryStats{
				Total:                3,
				Successes:            0,
				CurrentFailureStreak: 3,
			},
			hasSuccessRate:  true,
			wantSuccessRate: 0,
		},
		"all success": {
			history: health.History{check(0), check(1), check(2)},
			want: health.HistoryStats{
				Total:                3,
				Successes:            3,
				CurrentFailureStreak: 0,
			},
			hasSuccessRate:  true,
			wantSuccessRate: 1,
		},
		"multiple failure streaks": {
			history: health.History{failCheck(0), failCheck(1), check(2), failCheck(3), failCheck(4), failCheck(5)},
			want: health.HistoryStats{
				Total:                6,
				Successes:            1,
				CurrentFailureStreak: 3,
			},
			hasSuccessRate:  true,
			wantSuccessRate: 1.0 / 6.0,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tc.history.Stats()
			require.Equal(t, tc.want, got)
			gotRate, hasRate := got.SuccessRate()
			require.Equal(t, tc.hasSuccessRate, hasRate)
			require.Equal(t, tc.wantSuccessRate, gotRate)
		})
	}
}

func timestamp(minutes int) time.Time {
	baseTime := time.Date(2024, 2, 18, 12, 0, 0, 0, time.UTC)
	return baseTime.Add(time.Duration(minutes) * time.Minute)
}

func check(minutes int) health.Check {
	return health.Check{
		NodeID:         uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
		URL:            *test.Must(url.Parse("http://localhost/test")),
		Timestamp:      timestamp(minutes),
		Latency:        time.Second,
		HTTPStatusCode: http.StatusOK,
	}
}

func failCheck(mins int) health.Check {
	c := check(mins)
	c.HTTPStatusCode = http.StatusInternalServerError
	return c
}
