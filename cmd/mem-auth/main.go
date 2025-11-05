package main

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"os"

	"github.com/openpcc/openpcc/ahttp"
	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/auth/credentialing"
	"github.com/openpcc/openpcc/gateway"
	"github.com/openpcc/openpcc/gen/protos"
	"github.com/openpcc/openpcc/httpfmt"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/proton"
	"github.com/openpcc/openpcc/transparency"
	"github.com/openpcc/openpcc/transparency/statements"
)

type configHandler struct{}

func (h configHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("SERVING CONFIG")

	relay := protos.OHTTPRelay{}
	relay.SetUrl("http://localhost:3100")

	verifier, err := test.LocalDevVerifier()
	if err != nil {
		fmt.Println("failed to create verifier", "error", err)
		os.Exit(1)
	}

	finder := transparency.NewStatementFinder(test.LocalDevTransparencyFSStore(), verifier, test.LocalDevIdentityPolicy())

	currencyKeyBundleResults, err := finder.FindStatements(r.Context(), transparency.StatementBundleQuery{
		PredicateType: statements.PublicKeyPredicateType,
	})
	if err != nil || len(currencyKeyBundleResults) != 1 {
		fmt.Println("failed to find currency key bundle", "error", err)
		os.Exit(1)
	}

	currencyBundle := currencyKeyBundleResults[0].Bundle

	ohttpKeyConfigsBundleResults, err := finder.FindStatements(r.Context(), transparency.StatementBundleQuery{
		PredicateType: statements.OHTTPKeyConfigsPredicateType,
	})
	if err != nil || len(ohttpKeyConfigsBundleResults) != 1 {
		fmt.Println("failed to find ohttp key configs bundle", "error", err)
		os.Exit(1)
	}

	ohttpKeyConfigsBundle := ohttpKeyConfigsBundleResults[0].Bundle

	cfg := protos.AuthConfigResponse_builder{
		BankUrl:               func() *string { s := "http://" + gateway.ExternalBankHost; return &s }(),
		RouterUrl:             func() *string { s := "http://" + gateway.ExternalRouterHost; return &s }(),
		Relays:                []*protos.OHTTPRelay{&relay},
		OhttpKeyConfigsBundle: ohttpKeyConfigsBundle,
		CurrencyKeyBundle:     currencyBundle,
	}

	resp := cfg.Build()

	httpfmt.WriteBinaryProto(w, r, resp)
}

type authHandler struct {
	isAttestation bool
}

func (h authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("SERVING AUTH")

	var authMessage protos.AuthWithdrawalRequest
	decoder := proton.NewDecoder(r.Body)
	if err := decoder.Decode(&authMessage); err != nil {
		fmt.Println("failed to decode auth message", "error", err)
		os.Exit(1)
	}

	var value currency.Value
	err := value.UnmarshalProto(authMessage.GetValue())
	if err != nil {
		fmt.Println("failed to unmarshal value", "error", err)
		os.Exit(1)
	}

	fmt.Println("value", value)

	if h.isAttestation {
		if value != ahttp.AttestationCurrencyValue {
			fmt.Println("value is not an attestation request")
			os.Exit(1)
		}
	}

	req := anonpay.BlindSignRequest{
		Value:          value,
		BlindedMessage: authMessage.GetBlindedMessage(),
	}

	creditIssuer := anonpaytest.MustNewIssuer()
	blindSignature, err := creditIssuer.BlindSign(r.Context(), req)
	if err != nil {
		fmt.Println("failed to blind sign", "error", err)
		os.Exit(1)
	}

	// TODO: Perform the actual debit

	badgeKey, err := test.NewTestBadgeKeyProvider().PrivateKey()
	if err != nil {
		fmt.Println("failed to get badge key", "error", err)
		os.Exit(1)
	}

	creds := credentialing.Credentials{Models: []string{"my-model:1b"}}

	credBytes, err := creds.MarshalBinary()
	if err != nil {
		fmt.Println("failed to marshal credentials", "error", err)
		os.Exit(1)
	}

	sig := ed25519.Sign(badgeKey, credBytes)

	badge := &credentialing.Badge{
		Credentials: creds,
		Signature:   sig,
	}

	badgeProto, err := badge.MarshalProto()
	if err != nil {
		fmt.Println("failed to marshal badge", "error", err)
		os.Exit(1)
	}

	resp := protos.AuthWithdrawalResponse_builder{
		BlindSignature: blindSignature,
		Badge:          badgeProto,
	}.Build()

	httpfmt.WriteBinaryProto(w, r, resp)
}

type refundHandler struct{}

func (h refundHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("SERVING REFUND")

	var refundMessage protos.AuthRefundRequest
	decoder := proton.NewDecoder(r.Body)
	if err := decoder.Decode(&refundMessage); err != nil {
		fmt.Println("failed to decode auth message", "error", err)
		os.Exit(1)
	}

	var credit anonpay.BlindedCredit
	if err := credit.UnmarshalProto(refundMessage.GetCredit()); err != nil {
		fmt.Println("failed to unmarshal credit", "error", err)
		os.Exit(1)
	}

	fmt.Println("credit", credit)

	creditIssuer := anonpaytest.MustNewIssuer()
	creditProcessor := anonpay.NewProcessor(creditIssuer, &anonpaytest.NoopNonceLocker{})

	tx, err := creditProcessor.BeginTransaction(r.Context(), &credit)
	if err != nil {
		fmt.Println("failed to begin transaction", "error", err)
		os.Exit(1)
	}

	// TODO: Perform the actual credit

	err = tx.Commit()
	if err != nil {
		fmt.Println("failed to commit transaction", "error", err)
		os.Exit(1)
	}

	w.WriteHeader(http.StatusOK)
}

func main() {
	fmt.Println("AUTH THIME")

	mux := http.NewServeMux()
	// mux.Handle("/auth", deps.WASMDemo)
	mux.Handle("/api/config", configHandler{})
	mux.Handle("/api/auth", authHandler{})
	mux.Handle("/api/attestationRequest", authHandler{isAttestation: true})
	mux.Handle("/api/refund", refundHandler{})

	// nosemgrep: go.lang.security.audit.net.use-tls.use-tls
	http.ListenAndServe(":3000", mux)
}
