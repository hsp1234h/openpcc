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

package inttest

import (
	"io"
	"strings"
	"testing"

	"log/slog"

	slogenv "github.com/cbrewster/slog-env"
	"github.com/neilotoole/slogt"
)

// WrapLog wraps the default logger with a new logger that can be used in tests.
func WrapLog(t *testing.T) *slog.Logger {
	// Only wrap if verbose is turned on for testing
	if !testing.Verbose() {
		return slog.Default()
	}
	replacer := func(_ []string, a slog.Attr) slog.Attr {
		const prefix = "/T/"
		if a.Key == slog.TimeKey {
			return slog.String(a.Key, a.Value.Time().Format("15:04:05.000"))
		}
		if a.Key == slog.SourceKey {
			if source, ok := a.Value.Any().(*slog.Source); ok {
				// Split the file path on the module name, and keep the last half
				// This is to make the logs more readable
				parts := strings.Split(source.File, prefix)
				if len(parts) == 2 {
					source.File = parts[1]
				}
			}
		}
		return a
	}

	f := slogt.Factory(func(w io.Writer) slog.Handler {
		opts := &slog.HandlerOptions{
			AddSource:   true,
			ReplaceAttr: replacer,
		}
		return slogenv.NewHandler(slog.NewTextHandler(w, opts), slogenv.WithDefaultLevel(slog.LevelError))
	})

	sl := slogt.New(t, f)

	slog.SetDefault(sl)
	return sl
}
