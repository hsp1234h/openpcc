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

package agent_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	ev "github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/router/agent"
	"github.com/openpcc/openpcc/uuidv7"
	"github.com/stretchr/testify/require"
)

func TestClientShutdownSendsEvent(t *testing.T) {
	var receivedEvent *agent.NodeEvent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		event := &agent.NodeEvent{}
		err := event.UnmarshalBinary(data)
		require.NoError(t, err)
		receivedEvent = event
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	agentConfig := agent.DefaultConfig()
	agentConfig.RouterBaseURL = server.URL
	agentConfig.NodeTargetURL = "http://localhost/target"
	agentConfig.NodeHealthcheckURL = "http://localhost/_health"
	agentUUID := uuidv7.MustNew()

	client, err := agent.New(agentUUID, agentConfig, testEvidence())
	require.NoError(t, err)

	err = client.Shutdown(context.Background())
	require.NoError(t, err)

	require.NotNil(t, receivedEvent)
	require.Equal(t, agentUUID, receivedEvent.NodeID)
	require.Nil(t, receivedEvent.Heartbeat) // shutdown indicator
}

func testEvidence() ev.SignedEvidenceList {
	return ev.SignedEvidenceList{
		&ev.SignedEvidencePiece{
			Type: ev.EventLog,
			Data: []byte("test"),
		},
	}
}
