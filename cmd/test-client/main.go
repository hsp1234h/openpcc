package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
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
	cfg.TransparencyIdentityPolicy = &devPolicy

	client, err := openpcc.NewFromConfig(ctx, cfg, openpcc.WithFakeAttestationSecret("123456"))
	if err != nil {
		return fmt.Errorf("failed to create confsec client: %w", err)
	}

	bod := "{\"model\":\"test-model\",\"prompt\":\"write a short story in the voice of jane austen about someone horrified at the treatment of pokemon in 1800s england\"}"
	// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.http-customized-request.http-customized-request
	req, err := http.NewRequest("POST", "http://confsec.invalid/generate", strings.NewReader(bod))
	if err != nil {
		return err
	}
	req.Header.Add("X-Confsec-Node-Tags", "test-model")

	fmt.Println("Attempting Request")
	resp, err := client.RoundTrip(req)
	if err != nil {
		return err
	}

	rawResp, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return err
	}

	fmt.Printf("Received response: \n%s\n", rawResp)

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
