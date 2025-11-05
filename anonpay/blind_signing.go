package anonpay

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cloudflare/circl/blindsign/blindrsa/partiallyblindrsa"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/otel/otelutil"
)

var hashFunc = crypto.SHA384.HashFunc()

// The Verify function assumes a salt of length hashFunc.Size(), so we provide a correct length salt initialized to all zeros.
// We do not need a salt because our nonce already contains sufficient randomness for security.
var zeroSalt = make([]byte, hashFunc.Size())

type blindSigner struct {
	signer partiallyblindrsa.Signer
}

func newBlindSigner(sk *rsa.PrivateKey) (*blindSigner, error) {
	signer, err := partiallyblindrsa.NewSigner(sk, hashFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return &blindSigner{
		signer: signer,
	}, nil
}

func (s *blindSigner) blindSign(ctx context.Context, value currency.Value, blindedMessage []byte) ([]byte, error) {
	_, span := otelutil.Tracer.Start(ctx, "anonpay.signer.blindSign")
	defer span.End()

	metadata, err := value.BlindBytes()
	if err != nil {
		return nil, otelutil.Errorf(span, "failed to marshal currency: %w", err)
	}

	blindedSignature, err := s.signer.BlindSign(blindedMessage, metadata)
	if err != nil {
		return nil, otelutil.Errorf(span, "failed to sign blinded message: %w", err)
	}

	return blindedSignature, nil
}

type blindVerifier struct {
	// mutex is required to prevent a panic that can happen
	// when verifier.FixedBlind is called concurrently.
	mu       *sync.Mutex
	pk       *rsa.PublicKey
	verifier partiallyblindrsa.Verifier
}

func newBlindVerifier(pk *rsa.PublicKey) *blindVerifier {
	return &blindVerifier{
		mu:       &sync.Mutex{},
		pk:       pk,
		verifier: partiallyblindrsa.NewVerifier(pk, hashFunc),
	}
}

func (v *blindVerifier) verifyCredit(ctx context.Context, c AnyCredit) error {
	_, span := otelutil.Tracer.Start(ctx, "anonpay.blindVerifier.verifyCredit")
	defer span.End()

	msg, err := c.Nonce().BlindBytes()
	if err != nil {
		return fmt.Errorf("failed to get nonce blind bytes: %w", err)
	}
	metadata, err := c.Value().BlindBytes()
	if err != nil {
		return fmt.Errorf("failed to get currency blind bytes: %w", err)
	}
	err = v.verifier.Verify(msg, metadata, c.Signature())
	if err != nil {
		return VerificationError{
			Err: err,
		}
	}
	return nil
}

func (v *blindVerifier) newUnsignedCredit(ctx context.Context, value currency.Value) ([]byte, *unsignedCreditState, error) {
	_, span := otelutil.Tracer.Start(ctx, "anonpay.blindVerifier.newUnsignedCredit")
	defer span.End()

	r, rInv, err := generateBlindingFactor(v.pk.N)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate blinding factor: %w", err)
	}

	nonce, err := RandomNonce()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare nonce: %w", err)
	}

	msg, err := nonce.BlindBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal nonce: %w", err)
	}

	metadata, err := value.BlindBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal currency: %w", err)
	}

	// locking required to prevent a panic in FixedBlind.
	v.mu.Lock()
	blindedMessage, state, err := v.verifier.FixedBlind(msg, metadata, zeroSalt, r.Bytes(), rInv.Bytes())
	v.mu.Unlock()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to blind message: %w", err)
	}

	return blindedMessage, &unsignedCreditState{
		ctx:       ctx,
		mu:        &sync.Mutex{},
		finalized: false,
		nonce:     nonce,
		state:     state,
	}, nil
}

type unsignedCreditState struct {
	ctx       context.Context
	mu        *sync.Mutex
	finalized bool
	nonce     Nonce
	state     partiallyblindrsa.VerifierState
}

func (c *unsignedCreditState) finalize(blindSignature []byte) (Nonce, []byte, error) {
	_, span := otelutil.Tracer.Start(c.ctx, "anonpay.unsignedCredit.finalize")
	defer span.End()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.finalized {
		return Nonce{}, nil, errors.New("credit already finalized")
	}

	signature, err := c.state.Finalize(blindSignature)
	if err != nil {
		return Nonce{}, nil, fmt.Errorf("failed to finalize: %w", err)
	}

	if c.nonce.UnsafeIncrement {
		// We are using a nonce that is unsafe to use immediately.
		safeTime := time.Unix(RoundDownNonceTimestamp(time.Now().Unix())+NonceMinimumSafeTimeSeconds, 0)
		slog.InfoContext(c.ctx, "waiting for nonce to be safe", "safeTime", safeTime)
		// We need to delay until the safe time before using this nonce.
		time.Sleep(time.Until(safeTime))
	}

	c.finalized = true

	return c.nonce, signature, nil
}
