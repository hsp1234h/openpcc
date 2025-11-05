package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/banking"
	"github.com/openpcc/openpcc/anonpay/currency"
	pb "github.com/openpcc/openpcc/gen/protos/anonpay/banking"
	"github.com/openpcc/openpcc/httpfmt"
	"github.com/openpcc/openpcc/proton"
)

// Server serves as bank implementation using the OpenPCC Banking HTTP API.
type Server struct {
	bank    banking.BlindBankContract
	handler http.Handler
}

func NewServer(bank banking.BlindBankContract) *Server {
	mux := http.NewServeMux()
	mux.Handle("POST /deposit", NewDepositHandler(bank))
	mux.Handle("POST /withdraw", NewWithdrawBatchHandler(bank))
	mux.Handle("POST /withdraw-full", NewWithdrawFullUnblinded(bank))
	mux.Handle("POST /exchange", NewExchangeHandler(bank))
	mux.Handle("POST /balance", NewBalanceHandler(bank))
	return &Server{
		bank:    bank,
		handler: mux,
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func NewDepositHandler(bank banking.BlindBankContract) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var message pb.DepositRequest
		decoder := proton.NewDecoder(r.Body)
		if err := decoder.Decode(&message); err != nil {
			slog.ErrorContext(r.Context(), "failed to read or unmarshal body proto", "error", err)
			httpfmt.BinaryServerError(w, r)
			return
		}
		account, err := banking.AccountTokenFromSecretBytes(message.GetAccountToken())
		if err != nil {
			httpfmt.BinaryBadRequest(w, r, "invalid account")
			return
		}
		var credit anonpay.BlindedCredit
		if err := credit.UnmarshalProto(message.GetCredit()); err != nil {
			slog.ErrorContext(r.Context(), "failed to unmarshal credit", "error", err)
			httpfmt.BinaryBadRequest(w, r, "failed to unmarshal credit")
			return
		}
		balance, err := bank.Deposit(r.Context(), []byte{}, account, &credit)
		if err != nil {
			writeErrorResponse(w, r, err)
			return
		}
		response := pb.DepositResponse_builder{
			Balance: &balance,
		}.Build()
		httpfmt.WriteBinaryProto(w, r, response)
	}
}

func NewWithdrawBatchHandler(bank banking.BlindBankContract) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var batch pb.BatchWithdrawRequest
		decoder := proton.NewDecoder(r.Body)
		if err := decoder.Decode(&batch); err != nil {
			slog.ErrorContext(r.Context(), "failed to read or unmarshal body proto", "error", err)
			httpfmt.BinaryServerError(w, r)
			return
		}
		if !batch.HasAccountToken() {
			slog.ErrorContext(r.Context(), "missing account token")
			httpfmt.BinaryBadRequest(w, r, "missing account token")
			return
		}
		account, err := banking.AccountTokenFromSecretBytes(batch.GetAccountToken())
		if err != nil {
			httpfmt.BinaryBadRequest(w, r, "invalid account")
			return
		}
		batchRequests := make([]anonpay.BlindSignRequest, 0)
		for _, request := range batch.GetRequests() {
			var value currency.Value
			if err := value.UnmarshalProto(request.GetValue()); err != nil {
				slog.ErrorContext(r.Context(), "failed to unmarshal value", "error", err)
				httpfmt.BinaryBadRequest(w, r, "failed to unmarshal value")
				return
			}
			blindedSigningRequest := anonpay.BlindSignRequest{
				Value:          value,
				BlindedMessage: request.GetBlindedMessage(),
			}
			batchRequests = append(batchRequests, blindedSigningRequest)
		}
		balance, signatures, err := bank.WithdrawBatch(r.Context(), []byte{}, account, batchRequests)
		if err != nil {
			writeErrorResponse(w, r, err)
			return
		}
		response := pb.BatchWithdrawResponse_builder{
			Balance:         &balance,
			BlindSignatures: signatures,
		}.Build()

		httpfmt.WriteBinaryProto(w, r, response)
	}
}

func NewWithdrawFullUnblinded(bank banking.BlindBankContract) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req pb.WithdrawFullUnblindedRequest
		decoder := proton.NewDecoder(r.Body)
		if err := decoder.Decode(&req); err != nil {
			slog.ErrorContext(r.Context(), "failed to read or unmarshal body proto", "error", err)
			httpfmt.BinaryServerError(w, r)
			return
		}

		if !req.HasAccountToken() {
			slog.ErrorContext(r.Context(), "missing account token")
			httpfmt.BinaryBadRequest(w, r, "missing account token")
			return
		}

		account, err := banking.AccountTokenFromSecretBytes(req.GetAccountToken())
		if err != nil {
			httpfmt.BinaryBadRequest(w, r, "invalid account")
			return
		}

		credit, err := bank.WithdrawFullUnblinded(r.Context(), []byte{}, account)
		if err != nil {
			writeErrorResponse(w, r, err)
			return
		}

		creditPB, err := credit.MarshalProto()
		if err != nil {
			slog.ErrorContext(r.Context(), "bank service failed to marshal credit", "error", err)
			httpfmt.BinaryServerError(w, r)
			return
		}

		response := pb.WithdrawFullUnblindedResponse_builder{
			Credit: creditPB,
		}.Build()

		httpfmt.WriteBinaryProto(w, r, response)
	}
}

func NewExchangeHandler(bank banking.BlindBankContract) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var message pb.ExchangeRequest
		decoder := proton.NewDecoder(r.Body)
		if err := decoder.Decode(&message); err != nil {
			slog.ErrorContext(r.Context(), "failed to read or unmarshal body proto", "error", err)
			httpfmt.BinaryServerError(w, r)
			return
		}

		var credit anonpay.BlindedCredit
		if err := credit.UnmarshalProto(message.GetCredit()); err != nil {
			slog.ErrorContext(r.Context(), "failed to unmarshal value", "error", err)
			httpfmt.BinaryBadRequest(w, r, "failed to unmarshal value")
			return
		}

		request := anonpay.BlindSignRequest{
			Value:          credit.Value(),
			BlindedMessage: message.GetBlindedMessage(),
		}

		signature, err := bank.Exchange(r.Context(), []byte{}, &credit, request)
		if err != nil {
			writeErrorResponse(w, r, err)
			return
		}

		response := pb.ExchangeResponse_builder{
			BlindSignature: signature,
		}.Build()

		httpfmt.WriteBinaryProto(w, r, response)
	}
}

func NewBalanceHandler(bank banking.BlindBankContract) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req pb.BalanceRequest
		decoder := proton.NewDecoder(r.Body)
		if err := decoder.Decode(&req); err != nil {
			slog.ErrorContext(r.Context(), "failed to read or unmarshal body proto", "error", err)
			httpfmt.BinaryServerError(w, r)
			return
		}

		if !req.HasAccountToken() {
			slog.ErrorContext(r.Context(), "missing account token")
			httpfmt.BinaryBadRequest(w, r, "missing account token")
			return
		}

		account, err := banking.AccountTokenFromSecretBytes(req.GetAccountToken())
		if err != nil {
			httpfmt.BinaryBadRequest(w, r, "invalid account")
			return
		}

		balance, err := bank.Balance(r.Context(), account)
		if err != nil {
			writeErrorResponse(w, r, err)
			return
		}

		response := pb.BalanceResponse_builder{
			Balance: &balance,
		}.Build()

		httpfmt.WriteBinaryProto(w, r, response)
	}
}

func writeErrorResponse(w http.ResponseWriter, r *http.Request, err error) {
	inputErr := anonpay.InputError{}
	if errors.As(err, &inputErr) {
		slog.ErrorContext(r.Context(), "user input error", "error", err)
		httpfmt.BinaryBadRequest(w, r, "invalid input")
		return
	}

	slog.ErrorContext(r.Context(), "bank error", "error", err)
	httpfmt.BinaryServerError(w, r)
}
