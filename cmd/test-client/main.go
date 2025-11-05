package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/openpcc/openpcc"
	"github.com/openpcc/openpcc/inttest"
)

func runTestClientCmd() error {
	ctx := context.Background()

	devPolicy := inttest.LocalDevIdentityPolicy()
	cfg := openpcc.DefaultConfig()
	cfg.APIURL = "http://localhost:3000"
	cfg.APIKey = "test-key"
	cfg.PingRouter = false
	cfg.TransparencyVerifier = inttest.LocalDevVerifierConfig()
	cfg.TransparencyIdentityPolicy = devPolicy

	client, err := openpcc.NewFromConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to create confsec client: %w", err)
	}

	bod := "This is a body"
	// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.http-customized-request.http-customized-request
	req, err := http.NewRequest("POST", "http://confsec.invalid:9999", strings.NewReader(bod))
	if err != nil {
		return err
	}

	fmt.Println("Attempting Request")
	resp, err := client.RoundTrip(req)
	if err != nil {
		return err
	}
	fmt.Println("RESP", resp)

	return nil
}

func main() {
	fmt.Println("This is a client")

	err := runTestClientCmd()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
