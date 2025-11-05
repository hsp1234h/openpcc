package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/noncelocking"
	pb "github.com/openpcc/openpcc/gen/protos/anonpay/noncelocking"
	"github.com/openpcc/openpcc/httpfmt"
	"google.golang.org/protobuf/proto"
)

// Server serves an [anonpay.NonceLocker] implementation using the OpenPCC Nonce Locking HTTP API.
type Server struct {
	locker  noncelocking.TicketLockerContract
	handler http.Handler
}

func NewServer(locker noncelocking.TicketLockerContract) *Server {
	mux := http.NewServeMux()
	mux.Handle("POST /lock", NewLockHandler(locker))
	mux.Handle("POST /consume", NewConsumeHandler(locker))
	mux.Handle("POST /release", NewReleaseHandler(locker))
	return &Server{
		locker:  locker,
		handler: mux,
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

type lockRequest struct {
	nonce anonpay.Nonce
}

func (lr *lockRequest) UnmarshalBinary(data []byte) error {
	req := pb.LockRequest{}
	if err := proto.Unmarshal(data, &req); err != nil {
		return err
	}
	return lr.nonce.UnmarshalProto(req.GetNonce())
}

type lockResponse struct {
	ticket string
}

func (lr *lockResponse) MarshalBinary() ([]byte, error) {
	return proto.Marshal(pb.LockResponse_builder{
		Ticket: &lr.ticket,
	}.Build())
}

func NewLockHandler(locker noncelocking.TicketLockerContract) http.Handler {
	return httpfmt.BinaryHandler(func(ctx context.Context, req *lockRequest) (*lockResponse, error) {
		ticket, err := locker.LockNonce(ctx, req.nonce)
		if err != nil {
			return nil, convertInputError(err)
		}
		return &lockResponse{
			ticket: ticket,
		}, nil
	})
}

type UnlockRequest struct {
	nonce  anonpay.Nonce
	ticket string
}

func (ur *UnlockRequest) UnmarshalBinary(data []byte) error {
	req := pb.UnlockRequest{}
	if err := proto.Unmarshal(data, &req); err != nil {
		return err
	}
	ur.ticket = req.GetTicket()
	return ur.nonce.UnmarshalProto(req.GetNonce())
}

func NewConsumeHandler(locker noncelocking.TicketLockerContract) http.Handler {
	return httpfmt.BinaryHandlerInputOnly(func(ctx context.Context, req *UnlockRequest) error {
		err := locker.ConsumeNonce(ctx, req.nonce, req.ticket)
		if err != nil {
			return convertInputError(err)
		}
		return nil
	})
}

func NewReleaseHandler(locker noncelocking.TicketLockerContract) http.Handler {
	return httpfmt.BinaryHandlerInputOnly(func(ctx context.Context, req *UnlockRequest) error {
		err := locker.ReleaseNonce(ctx, req.nonce, req.ticket)
		if err != nil {
			return convertInputError(err)
		}
		return nil
	})
}

func convertInputError(err error) error {
	var inputErr anonpay.InputError
	if errors.As(err, &inputErr) {
		return httpfmt.ErrorWithStatusCode{
			Err:           err,
			PublicMessage: "invalid input",
			StatusCode:    http.StatusBadRequest,
		}
	}

	if errors.Is(err, anonpay.ErrNonceLocked) {
		return httpfmt.ErrorWithStatusCode{
			Err:           err,
			PublicMessage: "nonce is locked",
			StatusCode:    http.StatusConflict,
		}
	}

	if errors.Is(err, anonpay.ErrNonceConsumed) {
		return httpfmt.ErrorWithStatusCode{
			Err:           err,
			PublicMessage: "nonce is consumed",
			StatusCode:    http.StatusGone,
		}
	}

	return err
}
