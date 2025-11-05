package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/openpcc/openpcc/gateway"
)

func main() {
	fmt.Println("gateway")

	keyActiveFrom, err := time.Parse(time.RFC3339, "2025-09-18T18:00:13.132674Z")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	keyActiveUntil, err := time.Parse(time.RFC3339, "2026-03-18T18:00:13.132674Z")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cfg := gateway.Config{
		Keys: []gateway.Key{
			{
				ID:          1,
				Seed:        "0f4eda2e6c806018fb1082a6b0d8dc30c3aee556b41ac47cda7db81a57985997",
				ActiveFrom:  keyActiveFrom,
				ActiveUntil: keyActiveUntil,
			},
		},
		BankURL:   "http://localhost:3500",
		RouterURL: "http://localhost:3400",
	}

	gateway, err := gateway.NewGateway(cfg)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// nosemgrep: go.lang.security.audit.net.use-tls.use-tls
	err = http.ListenAndServe(":3200", gateway)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
