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
	"math"
	"net/url"
	"time"

	"github.com/google/uuid"
	pb "github.com/openpcc/openpcc/gen/protos/router/health"
	"github.com/openpcc/openpcc/uuidv7"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Check struct {
	NodeID         uuid.UUID
	URL            url.URL
	Retries        int
	Timestamp      time.Time
	Latency        time.Duration
	HTTPStatusCode int
	ErrorMessage   string
}

func (c *Check) Equal(other Check) bool {
	return c.NodeID == other.NodeID &&
		c.URL.String() == other.URL.String() &&
		c.Retries == other.Retries &&
		c.Timestamp.Equal(other.Timestamp) &&
		c.Latency == other.Latency &&
		c.HTTPStatusCode == other.HTTPStatusCode &&
		c.ErrorMessage == other.ErrorMessage
}

func (c *Check) IsSuccessful() bool {
	return c.HTTPStatusCode >= 200 && c.HTTPStatusCode <= 299
}

func (c *Check) UnmarshalProto(pbc *pb.Check) error {
	id, err := uuidv7.Parse(pbc.GetNodeId())
	if err != nil {
		return fmt.Errorf("failed to parse node id: %w", err)
	}

	requestURL, err := url.Parse(pbc.GetUrl())
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	if requestURL.Scheme == "" {
		return errors.New("requires absolute URL")
	}

	c.NodeID = id
	c.URL = *requestURL
	c.Retries = int(pbc.GetRetries())
	c.Timestamp = pbc.GetTimestamp().AsTime()
	c.Latency = time.Nanosecond * time.Duration(pbc.GetLatencyNs())
	c.HTTPStatusCode = int(pbc.GetHttpStatusCode())
	c.ErrorMessage = pbc.GetErrorMessage()

	return nil
}

func (c *Check) MarshalProto() *pb.Check {
	pbc := &pb.Check{}

	pbc.SetNodeId(c.NodeID.String())
	pbc.SetUrl(c.URL.String())
	retries, ok := safeInt32(c.Retries)
	if !ok {
		retries = math.MaxInt32 // should not really happen, but need to keep linters happy.
	}
	pbc.SetRetries(retries)
	pbc.SetTimestamp(timestamppb.New(c.Timestamp))
	pbc.SetLatencyNs(c.Latency.Nanoseconds())
	statusCode, ok := safeInt32(c.HTTPStatusCode)
	if !ok {
		statusCode = math.MaxInt32 // should not really happen, but need to keep linters happy.
	}
	pbc.SetHttpStatusCode(statusCode)
	pbc.SetErrorMessage(c.ErrorMessage)

	return pbc
}

func (c *Check) MarshalBinary() ([]byte, error) {
	return proto.Marshal(c.MarshalProto())
}

func (c *Check) UnmarshalBinary(data []byte) error {
	pbc := &pb.Check{}
	err := proto.Unmarshal(data, pbc)
	if err != nil {
		return err
	}
	return c.UnmarshalProto(pbc)
}

func safeInt32(v int) (int32, bool) {
	if v < math.MinInt32 || v > math.MaxInt32 {
		return 0, false
	}

	return int32(v), true
}
