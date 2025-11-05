package inmem_test

import (
	"testing"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/banking"
	"github.com/openpcc/openpcc/anonpay/banking/inmem"
	"github.com/openpcc/openpcc/anonpay/banking/testcontract"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
)

func TestContract(t *testing.T) {
	testcontract.TestBlindBankContract(t, func(t *testing.T, nonceLocker anonpay.NonceLocker) (banking.BlindBankContract, error) {
		issuer := anonpaytest.MustNewIssuer()
		return inmem.NewBank(issuer, nonceLocker), nil
	})
}
