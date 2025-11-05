package anonpay

import (
	"bytes"
	"context"
	"crypto/rsa"

	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/otel/otelutil"
)

// Payee represents the party making a payment in the anonpay system.
//
// The payee prepares credits so that they can be signed by a [Signer].
type Payee struct {
	verifier *blindVerifier
}

func NewPayee(pk *rsa.PublicKey) *Payee {
	return &Payee{
		verifier: newBlindVerifier(pk),
	}
}

// BlindSignState contains the state of an open blind sign request.
//
// It can be finalized with a blinded signature to get the new blinded credit.
type BlindSignState struct {
	value          currency.Value
	blindedMessage []byte
	state          *unsignedCreditState
}

// Value returns the value of the unsigned credit.
func (c *BlindSignState) Value() currency.Value {
	return c.value
}

// Request returns the singing request that should be sent to the Issuer.
func (c *BlindSignState) Request() BlindSignRequest {
	return BlindSignRequest{
		Value:          c.value,
		BlindedMessage: bytes.Clone(c.blindedMessage),
	}
}

// Finalize takes the blind signature returned an Issuer and finalizes the credit.
//
// Once Finalize is called, the unsigned credit has been signed and should no longer be used.
// Any further calls to Finalize will return an error.
func (c *BlindSignState) Finalize(blindSignature []byte) (*BlindedCredit, error) {
	nonce, signature, err := c.state.finalize(blindSignature)
	if err != nil {
		return nil, err
	}

	return &BlindedCredit{
		value:     c.value,
		nonce:     nonce,
		signature: signature,
	}, nil
}

// BeginBlindedCredit returns a new signing request for
func (p *Payee) BeginBlindedCredit(ctx context.Context, value currency.Value) (*BlindSignState, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "anonpay.Payee.BeginBlindedCredit")
	defer span.End()

	blindedMessage, state, err := p.verifier.newUnsignedCredit(ctx, value)
	if err != nil {
		return nil, err
	}

	return &BlindSignState{
		value:          value,
		blindedMessage: blindedMessage,
		state:          state,
	}, nil
}

func (p *Payee) VerifyCredit(ctx context.Context, credit AnyCredit) error {
	ctx, span := otelutil.Tracer.Start(ctx, "anonpay.Payee.VerifyCredit")
	defer span.End()

	return p.verifier.verifyCredit(ctx, credit)
}
