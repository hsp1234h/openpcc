// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attest_test

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/google/go-eventlog/register"
	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/verify"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/transparency/statements"
	"github.com/stretchr/testify/require"
)

// These are all measurements from VM jfquinn-test-compute-base-tdx
// on google cloud, which was provisioned with our base image on Jun 22, 2025, 8:57:28 AM UTC-04:00
var (
	testPCRSHA256Values map[int]string = map[int]string{
		0: "0CCA9EC161B09288802E5A112255D21340ED5B797F5FE29CECCCFD8F67B9F802",
		1: "2F232B75625EEEA98CA57AE8CEF11E4CD00FEB3515DC969430596E183997E804",
		2: "ECD11E957F3B751BAF5E1764F1FE56EC4ACE4D0F73236FD6A905676925357A32",
		3: "3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969",
		4: "1BDC909E09F23D525D17EB72756C7966797C5D33C460F2327CB2C0072B345881",
		5: "A5CEB755D043F32431D63E39F5161464620A3437280494B5850DC1B47CC074E0",
		8: "D265F43867C6934D4D2E23B8D68E5E21567C3020B53A539A047078D81E493C8B",
	}
)

func readRSAPublicKeyFromPEM(pemData []byte) (*rsa.PublicKey, error) {
	// Decode the PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Parse the public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("failed to parse public key")
	}

	// Type assert to RSA public key
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPub, nil
}

func TestParseLog(t *testing.T) {
	t.Skip("skipping until we get an event log with secure boot enabled")
	testFS := test.TextArchiveFS(t, "testdata/tcg_eventlog.txt")
	testUEFIEventLog := test.ReadFile(t, testFS, "test_tcg_event_log.pem")
	testAKPubkey := test.ReadFile(t, testFS, "test_eventlog_akpub.pem")

	t.Run("success", func(t *testing.T) {
		imageManifest := &statements.ImageManifest{
			CustomData: &statements.BuildCustomData{
				KernelCmdlines: []statements.KernelCmdline{
					{
						ConfsecRoot: "3f729361d013276cf81e970ace1b855243e8ca09aacf611103fee2dcdfd95f09",
					},
				},
			},
		}
		block, _ := pem.Decode(testUEFIEventLog)
		mrs := []register.MR{}
		testReader := bytes.NewReader(block.Bytes)

		pcrs := []int{0, 1, 2, 3, 4, 5, 8}

		for _, pcrIndex := range pcrs {
			pcrDigest, err := hex.DecodeString(testPCRSHA256Values[pcrIndex])
			require.NoError(t, err)
			mrs = append(mrs, register.PCR{
				Index:     pcrIndex,
				DigestAlg: crypto.SHA256,
				Digest:    pcrDigest,
			})
		}

		attestor, err := attest.NewEventLogAttestor(
			testReader, mrs,
		)
		require.NoError(t, err)

		se, err := attestor.CreateSignedEvidence(t.Context())
		require.NoError(t, err)
		require.NotNil(t, se)

		rsaPub, err := readRSAPublicKeyFromPEM(testAKPubkey)

		require.NoError(t, err)

		err = verify.EventLog(t.Context(), rsaPub, mrs, se, imageManifest)
		require.NoError(t, err)
	})

	t.Run("failure, unexpected PCR", func(t *testing.T) {
		t.Skip("skipping until we get an event log with secure boot enabled")
		// See https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf#page=103
		block, _ := pem.Decode(testUEFIEventLog)
		mrs := []register.MR{}
		testReader := bytes.NewReader(block.Bytes)

		mrs = append(mrs, register.PCR{
			Index:     8,
			DigestAlg: crypto.SHA256,
			Digest:    []byte{},
		})

		attestor, err := attest.NewEventLogAttestor(
			testReader, mrs,
		)
		require.Nil(t, err)

		_, err = attestor.CreateSignedEvidence(t.Context())
		require.ErrorContains(t, err, "the following registers failed to replay: [8]")
	})
}
