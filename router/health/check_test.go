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

	"github.com/google/uuid"
	pb "github.com/openpcc/openpcc/gen/protos/router/health"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/router/health"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCheckMarshalUnmarshalProto(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		timestamp := time.Now().UTC().Round(0)

		pbc := &pb.Check{}
		pbc.SetNodeId(uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6").String())
		pbc.SetUrl("http://localhost/test")
		pbc.SetRetries(3)
		pbc.SetTimestamp(timestamppb.New(timestamp))
		pbc.SetLatencyNs(time.Second.Nanoseconds())
		pbc.SetHttpStatusCode(http.StatusOK)
		pbc.SetErrorMessage("test")

		got := &health.Check{}
		err := got.UnmarshalProto(pbc)
		require.NoError(t, err)

		want := &health.Check{
			NodeID:         uuidv7.MustParse("01954bd0-f3c3-740e-b149-ad06ad1cebf6"),
			URL:            *test.Must(url.Parse("http://localhost/test")),
			Retries:        3,
			Timestamp:      timestamp,
			Latency:        time.Second,
			HTTPStatusCode: http.StatusOK,
			ErrorMessage:   "test",
		}

		require.Equal(t, want, got)

		// check again but with non-hardcoded pb
		pbc = got.MarshalProto()
		err = got.UnmarshalProto(pbc)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	failTests := map[string]func(*pb.Check){
		"fail, invalid UUID": func(c *pb.Check) {
			c.SetNodeId("test")
		},
		"fail, invalid UUID version": func(c *pb.Check) {
			id := uuid.New() // v1 uuid
			c.SetNodeId(id.String())
		},
		"fail, invalid URL": func(c *pb.Check) {
			c.SetUrl("://://")
		},
		"fail, relative URL": func(c *pb.Check) {
			c.SetUrl("/test")
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			timestamp := time.Now().UTC().Round(0)

			pbc := &pb.Check{}
			pbc.SetNodeId(uuidv7.MustNew().String())
			pbc.SetUrl("http://localhost/test")
			pbc.SetRetries(3)
			pbc.SetTimestamp(timestamppb.New(timestamp))
			pbc.SetLatencyNs(time.Second.Nanoseconds())
			pbc.SetHttpStatusCode(http.StatusOK)
			pbc.SetErrorMessage("")

			tc(pbc)

			c := &health.Check{}
			err := c.UnmarshalProto(pbc)
			require.Error(t, err)
		})
	}
}
