package anonpay

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/blindsign/blindrsa"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/otel/otelutil"
)

// Issuer represents the party that is responsible for issuing credits.
type Issuer struct {
	signer *blindSigner
	// for simplicity of implementation the Issuer uses a blindVerifier to create unblinded credits.
	verifier *blindVerifier
}

// NewIssuer returns a new Issuer for a given private key, or returns an error if that private key is not safe for blind signing.
//
// The blind with metadata protocol used here requires the private key to be made of two safe primes,
// which means they are equal to 2*p + 1 and 2*q + 1 where p and q are also prime.
func NewIssuer(sk *rsa.PrivateKey) (*Issuer, error) {
	signer, err := newBlindSigner(sk)
	if err != nil {
		return nil, err
	}

	return &Issuer{
		signer:   signer,
		verifier: newBlindVerifier(&sk.PublicKey),
	}, nil
}

func (i *Issuer) PublicKey() *rsa.PublicKey {
	return i.verifier.pk
}

// BlindSignRequest is the request sent from Payee to Issuer to blind sign a new credit.
type BlindSignRequest struct {
	Value          currency.Value
	BlindedMessage []byte
}

// BlindSign will sign the BlindedSigningRequest.
func (i *Issuer) BlindSign(ctx context.Context, request BlindSignRequest) ([]byte, error) {
	_, span := otelutil.Tracer.Start(ctx, "anonpay.Issuer.BlindSign")
	defer span.End()

	return i.signer.blindSign(ctx, request.Value, request.BlindedMessage)
}

func (i *Issuer) IssueUnblindedCredit(ctx context.Context, value currency.Value) (*UnblindedCredit, error) {
	_, span := otelutil.Tracer.Start(ctx, "anonpay.Issuer.IssueUnblindedCredit")
	defer span.End()

	blindedMessage, state, err := i.verifier.newUnsignedCredit(ctx, value)
	if err != nil {
		return nil, fmt.Errorf("failed to create unsigned credit: %w", err)
	}

	blindSignature, err := i.signer.blindSign(ctx, value, blindedMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to blind sign: %w", err)
	}

	nonce, signature, err := state.finalize(blindSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize: %w", err)
	}

	return &UnblindedCredit{
		value:     value,
		nonce:     nonce,
		signature: signature,
	}, nil
}

func (i *Issuer) VerifyCredit(ctx context.Context, credit AnyCredit) error {
	ctx, span := otelutil.Tracer.Start(ctx, "anonpay.Issuer.VerifyCredit")
	defer span.End()

	return i.verifier.verifyCredit(ctx, credit)
}

func generateBlindingFactor(n *big.Int) (*big.Int, *big.Int, error) {
	r, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, nil, err
	}

	if r.Sign() == 0 {
		r.SetInt64(1)
	}
	rInv := new(big.Int).ModInverse(r, n)
	if rInv == nil {
		return nil, nil, blindrsa.ErrInvalidBlind
	}

	return r, rInv, nil
}
