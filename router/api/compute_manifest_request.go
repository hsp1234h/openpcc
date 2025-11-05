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

package api

import (
	"fmt"

	pb "github.com/openpcc/openpcc/gen/protos/router"
	"github.com/openpcc/openpcc/tags"
	"google.golang.org/protobuf/proto"
)

const MaxComputeManifests = 500

// ComputeManifestRequest is the input for the router evidence endpoint.
type ComputeManifestRequest struct {
	Tags  tags.Tags
	Limit int
}

func (r *ComputeManifestRequest) UnmarshalProto(pbr *pb.ComputeManifestRequest) error {
	tagsList, err := tags.FromSlice(pbr.GetTags())
	if err != nil {
		return err
	}

	limit := int(pbr.GetLimit())
	if limit < 0 || limit > MaxComputeManifests {
		return fmt.Errorf("limit should be between 0-%d, got %d", MaxComputeManifests, limit)
	}

	r.Tags = tagsList
	r.Limit = limit

	return nil
}

func (r *ComputeManifestRequest) UnmarshalBinary(b []byte) error {
	pbr := &pb.ComputeManifestRequest{}
	err := proto.Unmarshal(b, pbr)
	if err != nil {
		return err
	}

	return r.UnmarshalProto(pbr)
}
