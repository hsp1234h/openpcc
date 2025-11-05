//go:build linux || darwin || freebsd || netbsd || openbsd

package chunk

import (
	"net"
	"net/http"
	"time"
)

// DefaultDialTimeout is the default timeout for dialing a connection.
// This should be used for services operating around Fastly's network,
// since fastly imposes a "time between bytes" timeout of 10 seconds
// today (we can adjust this limit if needed by reaching out to Fastly).
// We use 9 seconds instead of 10 to leave 1 second of headroom.
const DefaultDialTimeout = 9 * time.Second

// NewHTTPTransport returns a http transport that is configured
// to do minimal buffering.
func NewHTTPTransport(dialTimeout time.Duration) *http.Transport {
	dialer := &net.Dialer{
		Timeout: dialTimeout,
	}

	transport := &http.Transport{
		DisableCompression: true, // disable gzip as this involves buffering.
		DialContext:        dialer.DialContext,

		// Connection pooling configuration, inspire by Go's DefaultTransport.
		MaxIdleConnsPerHost: 100,              // Per-host, permit a maximum of 100 idle connections.
		IdleConnTimeout:     90 * time.Second, // Time out idle connections after 90 seconds.
		TLSHandshakeTimeout: 10 * time.Second, // 10 second timeout for TLS handshakes.
	}

	return transport
}
