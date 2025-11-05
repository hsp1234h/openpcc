package main

import (
	"fmt"
	"net/http"

	"github.com/openpcc/openpcc/anonpay/banking/httpapi"
	"github.com/openpcc/openpcc/anonpay/banking/inmem"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
)

func main() {
	fmt.Println("Runnin a bank")

	bank := inmem.NewBank(anonpaytest.MustNewIssuer(), &anonpaytest.NoopNonceLocker{})

	bankServer := httpapi.NewServer(bank)

	// nosemgrep: go.lang.security.audit.net.use-tls.use-tls
	http.ListenAndServe(":3500", bankServer)
}
