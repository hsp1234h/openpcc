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

package secrets_test

import (
	"bytes"
	"log"
	"log/slog"
	"testing"

	"github.com/openpcc/openpcc/internal/secrets"
	"github.com/stretchr/testify/require"
)

func TestStringLeak(t *testing.T) {
	// Ensure that regardless of how we try to use the secrets.String type, the
	// value is always redacted unless we explicitly consume it.
	s := secrets.NewString("secret")
	t.Run("String", func(t *testing.T) {
		require.Equal(t, "REDACTED", s.String())
	})
	t.Run("MarshalJSON", func(t *testing.T) {
		b, err := s.MarshalJSON()
		require.NoError(t, err)
		require.Equal(t, []byte(`"REDACTED"`), b)
	})
	t.Run("MarshalText", func(t *testing.T) {
		b, err := s.MarshalText()
		require.NoError(t, err)
		require.Equal(t, []byte("REDACTED"), b)
	})
	t.Run("MarshalYAML", func(t *testing.T) {
		b, err := s.MarshalYAML()
		require.NoError(t, err)
		require.Equal(t, "REDACTED", b)
	})
	t.Run("MarshalBinary", func(t *testing.T) {
		b, err := s.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, []byte("REDACTED"), b)
	})
	t.Run("Standard Log", func(t *testing.T) {
		buf := &bytes.Buffer{}
		log.SetOutput(buf)
		// Remove the prefix so we can compare the output
		log.SetFlags(0)
		log.Print(s)
		require.Equal(t, "REDACTED\n", buf.String())
	})
	t.Run("Slog", func(t *testing.T) {
		buf := &bytes.Buffer{}
		opts := &slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: false,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				// Remove time and level attributes
				if a.Key == "time" || a.Key == "level" || a.Key == "msg" {
					return slog.Attr{}
				}
				return a
			},
		}
		handler := slog.NewTextHandler(buf, opts)
		logger := slog.New(handler)
		logger.Info("test", "secret", s)
		require.Equal(t, "secret=REDACTED\n", buf.String())
	})
	t.Run("Equal", func(t *testing.T) {
		require.True(t, s.Equal(secrets.NewString("secret")))
		require.False(t, s.Equal(secrets.NewString("secrete")))
	})
	t.Run("UnmarshalJSON", func(t *testing.T) {
		s := secrets.NewString("")
		err := s.UnmarshalJSON([]byte(`"secret"`))
		require.NoError(t, err)
		require.Equal(t, "REDACTED", s.String())
		require.True(t, s.Equal(secrets.NewString("secret")))
	})
	t.Run("Consume", func(t *testing.T) {
		require.Equal(t, "secret", s.Consume())
		// ensure it is no longer the secret after being consumed
		require.NotEqual(t, "secret", s.Consume())
	})
}
