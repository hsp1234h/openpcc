package banking

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/openpcc/openpcc/internal/secrets"
)

// AccountTokenLength is the length of an account token in bytes.
const AccountTokenLength = 32

// AccountToken is a secret token that identifies a blind bank account.
//
// This is the secret identifier that allows access to a bank account. Anyone
// with access to this identifier can withdraw or deposit credits from the
// corresponding bank account.
//
// When storing an account token server-side be sure to treat it like the secret that it is.
//
// This type includes protections to prevent it from being logged by accident. Use `SecretBytes`
// method to access the actual underlying secret bytes.
type AccountToken struct {
	secret secrets.String
}

func AccountTokenFromSecretBytes(b []byte) (AccountToken, error) {
	if len(b) != AccountTokenLength {
		return AccountToken{}, fmt.Errorf("invalid account token length %d", len(b))
	}
	return AccountToken{
		secret: secrets.NewString(string(b)),
	}, nil
}

// GenerateAccountToken generates a random token using crypto/rand.Reader
func GenerateAccountToken() (AccountToken, error) {
	return GenerateAccountTokenFrom(rand.Reader)
}

// GenerateAccountTokenFrom uses the provided reader to generate a new account token.
//
// This function is mostly relevant for testing scenarios where you might need consistent account ID's between test runs.
//
// When used in production, the provided reader should be reading from a secure random reader, like the one in crypto/rand.
func GenerateAccountTokenFrom(r io.Reader) (AccountToken, error) {
	secretB := make([]byte, AccountTokenLength)
	_, err := io.ReadFull(r, secretB)
	if err != nil {
		return AccountToken{}, fmt.Errorf("failed to read random bytes: %w", err)
	}

	return AccountToken{
		secret: secrets.NewString(string(secretB)),
	}, nil
}

// SecretBytes returns the secret bytes of this token so they can be used.
func (t AccountToken) SecretBytes() []byte {
	return t.secret.Bytes()
}
