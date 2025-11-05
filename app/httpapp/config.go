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

package httpapp

import "time"

type Config struct {
	// Port is the port this a http server will be exposed on.
	Port string `yaml:"port"`

	// ReadTimeout is the maximum duration for reading the entire
	// request, including the body. A zero or negative value means
	// there will be no timeout.
	//
	// Because ReadTimeout does not let Handlers make per-request
	// decisions on each request body's acceptable deadline or
	// upload rate, most users will prefer to use
	// ReadHeaderTimeout. It is valid to use them both.
	ReadTimeout time.Duration `yaml:"read_timeout"`

	// ReadHeaderTimeout is the amount of time allowed to read
	// request headers. The connection's read deadline is reset
	// after reading the headers and the Handler can decide what
	// is considered too slow for the body. If zero, the value of
	// ReadTimeout is used. If negative, or if zero and ReadTimeout
	// is zero or negative, there is no timeout.
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`

	// WriteTimeout is the maximum duration before timing out
	// writes of the response. It is reset whenever a new
	// request's header is read. Like ReadTimeout, it does not
	// let Handlers make decisions on a per-request basis.
	// A zero or negative value means there will be no timeout.
	WriteTimeout time.Duration `yaml:"write_timeout"`

	// RequestLogging indicates whether request logging is enabled
	// defaults to true.
	RequestLogging bool `yaml:"request_logging"`

	// BodyLimit is the maximum size of the request body in bytes.
	// If zero, the default value of 1MB is used.
	BodyLimit string `yaml:"body_limit"`

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled. If zero, the
	// value of ReadTimeout is used.
	IdleTimeout time.Duration `yaml:"idle_timeout"`
}

func DefaultConfig() *Config {
	return &Config{
		Port:              "8000",
		ReadTimeout:       300 * time.Second, // quite generous, but better than no timeout.
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		RequestLogging:    true,
		BodyLimit:         "1M",
	}
}

// DefaultStreamingConfig returns a configuration suitable
// for streaming responses.
func DefaultStreamingConfig() *Config {
	cfg := DefaultConfig()
	cfg.WriteTimeout = 300 * time.Second // streaming long responses can take a while.
	return cfg
}
