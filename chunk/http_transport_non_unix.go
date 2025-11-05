//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package chunk

import (
	"net"
	"net/http"
	"runtime"
	"time"
)

// DefaultDialTimeout is the default timeout for dialing a connection.
// On non-unix builds, we aren't using fastly, so we can use a longer timeout.
const DefaultDialTimeout = 30 * time.Second

// NewHTTPTransport returns a http transport that is configured
// to do minimal buffering.
func NewHTTPTransport(dialTimeout time.Duration) *http.Transport {
	// WASM can't handle custom dialers, so use defaults
	if runtime.GOARCH == "wasm" {
		return &http.Transport{
			DisableCompression: true,
		}
	}

	// Other platforms get custom timeout
	dialer := &net.Dialer{
		Timeout: dialTimeout,
	}

	return &http.Transport{
		DisableCompression: true,
		DialContext:        dialer.DialContext,

		// Connection pooling configuration, inspire by Go's DefaultTransport.
		MaxIdleConnsPerHost: 100,              // Per-host, permit a maximum of 100 idle connections.
		IdleConnTimeout:     90 * time.Second, // Time out idle connections after 90 seconds.
		TLSHandshakeTimeout: 10 * time.Second, // 10 second timeout for TLS handshakes.
	}
}
