package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/openpcc/openpcc/chunk"
)

func main() {
	fmt.Println("oh relay")

	// forward to gateway
	uri, err := url.Parse("http://localhost:3200")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	proxy := &httputil.ReverseProxy{
		// immediately flush the response as we get them
		FlushInterval: -1,
		// Use a chunk-friendly transport.
		Transport: chunk.NewHTTPTransport(chunk.DefaultDialTimeout),
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = uri
			// for k, v := range c.InjectHeaders {
			// 	pr.Out.Header.Set(k, v)
			// }
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.ErrorContext(r.Context(), "proxy error", "error", err, "method", r.Method, "path", r.URL.Path)
			http.Error(w, "Proxy error", http.StatusBadGateway)
		},
	}

	// nosemgrep: go.lang.security.audit.net.use-tls.use-tls
	http.ListenAndServe(":3100", proxy)
}
