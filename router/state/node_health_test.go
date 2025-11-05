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

package state_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	pb "github.com/openpcc/openpcc/gen/protos/router/cluster"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/router/health"
	"github.com/openpcc/openpcc/router/state"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/require"
)

func TestNodeHealthMergeHealthcheck(t *testing.T) {
	tests := map[string]struct {
		before func() *state.NodeHealth
		event  func() health.Check
		after  func() *state.NodeHealth
	}{
		"changes, healthcheck inserted in empty history": {
			before: func() *state.NodeHealth {
				return &state.NodeHealth{
					History: health.History{},
				}
			},
			event: func() health.Check {
				return healthcheck(0)
			},
			after: func() *state.NodeHealth {
				return &state.NodeHealth{
					History: health.History{healthcheck(0)},
				}
			},
		},
		"no changes, healthcheck already in history": {
			before: func() *state.NodeHealth {
				return &state.NodeHealth{
					History: health.History{healthcheck(0)},
				}
			},
			event: func() health.Check {
				return healthcheck(0)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := tc.before()
			changes := h.MergeHealthcheck(tc.event())
			if tc.after == nil {
				require.False(t, changes)
				require.Equal(t, tc.before(), h)
				return
			}

			require.True(t, changes)
			require.Equal(t, tc.after(), h)
		})
	}
}

func TestNodeHealthMergeState(t *testing.T) {
	tests := map[string]struct {
		before func() *state.NodeHealth
		other  func() *state.NodeHealth
		after  func() *state.NodeHealth
	}{
		"no changes, both have empty history": {
			before: func() *state.NodeHealth {
				return &state.NodeHealth{
					History: health.History{},
				}
			},
			other: func() *state.NodeHealth {
				return &state.NodeHealth{
					History: health.History{},
				}
			},
		},
		"no changes, same history": {
			before: func() *state.NodeHealth {
				return &state.NodeHealth{
					History: health.History{healthcheck(0)},
				}
			},
			other: func() *state.NodeHealth {
				return &state.NodeHealth{
					History: health.History{healthcheck(0)},
				}
			},
		},
		"changes, different histories": {
			before: func() *state.NodeHealth {
				return &state.NodeHealth{
					History: health.History{healthcheck(0)},
				}
			},
			other: func() *state.NodeHealth {
				return &state.NodeHealth{
					History: health.History{healthcheck(1)},
				}
			},
			after: func() *state.NodeHealth {
				return &state.NodeHealth{
					History: health.History{healthcheck(0), healthcheck(1)},
				}
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := tc.before()
			changes := h.MergeState(tc.other())
			if tc.after == nil {
				require.False(t, changes)
				require.Equal(t, tc.before(), h)
				return
			}

			require.True(t, changes)
			require.Equal(t, tc.after(), h)
		})
	}
}

func TestNodeHealthMarshalUnmarshalProto(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		t.Parallel()

		his := health.History{
			healthcheck(0),
			healthcheck(1),
			healthcheck(2),
		}

		pbnh := &pb.NodeHealthState{}
		pbnh.SetHistory(his.MarshalProto())

		want := &state.NodeHealth{
			History: his,
		}

		got := &state.NodeHealth{}
		err := got.UnmarshalProto(pbnh)
		require.NoError(t, err)
		require.Equal(t, want, got)

		// check again but with non-hardcoded pb
		pbnh = got.MarshalProto()
		err = got.UnmarshalProto(pbnh)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	failTests := map[string]func(pbnh *pb.NodeHealthState){
		"fail, missing history": func(pbnh *pb.NodeHealthState) {
			pbnh.ClearHistory()
		},
		"fail, invalid history": func(pbnh *pb.NodeHealthState) {
			// invalid, checks out of order.
			his := health.History{
				healthcheck(1),
				healthcheck(0),
			}
			pbnh.SetHistory(his.MarshalProto())
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			his := health.History{
				healthcheck(0),
				healthcheck(1),
				healthcheck(2),
			}

			pbnh := &pb.NodeHealthState{}
			pbnh.SetHistory(his.MarshalProto())

			tc(pbnh)

			s := &state.NodeHealth{}
			err := s.UnmarshalProto(pbnh)
			require.Error(t, err)
		})
	}
}

func healthcheck(minutes int) health.Check {
	return health.Check{
		NodeID:         uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
		URL:            *test.Must(url.Parse("http://localhost/test")),
		Timestamp:      timestamp(minutes),
		Latency:        time.Second,
		HTTPStatusCode: http.StatusOK,
	}
}
