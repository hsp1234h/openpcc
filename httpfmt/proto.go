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

package httpfmt

import (
	"log/slog"
	"net/http"

	"google.golang.org/protobuf/proto"
)

func WriteBinaryProto(w http.ResponseWriter, r *http.Request, message proto.Message) {
	body, err := proto.Marshal(message)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to marshal response proto", "error", err)
		BinaryServerError(w, r)
		return
	}

	WriteBinary(w, r, body, http.StatusOK)
}
