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

type Status string

const (
	// StatusOK means a compute node is functioning normally and can receive traffic.
	StatusOK Status = "ok"
	// StatusUnavailable means a compute node is not responding or consistently failing.
	StatusUnavailable Status = "unavailable"
	// StatusUnknown means we don't have enough data to determine a node status.
	StatusUnknown Status = "unknown"
)
