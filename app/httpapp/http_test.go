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

package httpapp_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/openpcc/openpcc/app/httpapp"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/stretchr/testify/require"
)

func TestHTTPApp(t *testing.T) {
	t.Run("ok, run and shutdown", func(t *testing.T) {
		port := test.FreePort(t)

		a := httpapp.HTTP{
			&http.Server{
				Addr: fmt.Sprintf(":%d", port),
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, err := w.Write([]byte("Hello world!"))
					require.NoError(t, err)
				}),
			},
		}

		done := make(chan struct{})

		go func() {
			err := a.Run()
			require.NoError(t, err)
			close(done)
		}()

		timeout := 10 * time.Millisecond
		client := &http.Client{
			Timeout: timeout,
		}
		require.Eventually(t, func() bool {
			resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d", port))
			if err != nil {
				return false
			}
			defer resp.Body.Close()

			return resp.StatusCode == http.StatusOK
		}, 1*time.Second, timeout)

		err := a.Shutdown(t.Context())
		require.NoError(t, err)

		// wait for run to end.
		<-done
	})
}
