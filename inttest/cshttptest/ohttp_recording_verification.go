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

package cshttptest

import (
	"strconv"
	"strings"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/confidentsecurity/twoway"
	"github.com/openpcc/openpcc/messages"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

var (
	// Expected HPKE suite.
	kemID  = hpke.KEM_X25519_KYBER768_DRAFT00
	aeadID = hpke.AEAD_AES128GCM
	// innerChunkLen is the length of the payload chunks we're sending via OHTTP.
	innerChunkLen                  = messages.EncapsulatedChunkLen()
	unchunkedRequestOHTTPOverhead  = twoway.BinaryRequestHeaderLen + kemID.Scheme().CiphertextSize() + int(aeadID.CipherLen(0))
	unchunkedResponseOHTTPOverhead = int(max(aeadID.KeySize(), aeadID.NonceSize())) + int(aeadID.CipherLen(0))
	chunkedRequestOHTTPHeader      = twoway.BinaryRequestHeaderLen + kemID.Scheme().CiphertextSize()
	chunkedResponseOHTTPHeader     = int(max(aeadID.KeySize(), aeadID.NonceSize()))
	emptyFooterChunkLen            = 1 + int(aeadID.CipherLen(0))
	idealOHTTPBodyChunk            = innerChunkLen + quicvarint.Len(uint64(innerChunkLen)) + int(aeadID.CipherLen(0))
)

func RequireRawOHTTPRequest(t *testing.T, msg string) {
	header := HeaderSectionOnly(msg)
	body := CutHeaderSection(msg)
	if !isChunked(header) {
		RequireUnchunkedOHTTPMessage(t, unchunkedRequestOHTTPOverhead, header, body)
		return
	}
	// chunks are HTTP chunks on the body of the OHTTP message.
	chunks, err := ParseBodyChunks(body)
	require.NoError(t, err)

	RequireExactOHTTPRequestChunkLengths(t, chunks)
}

func RequireRawOHTTPResponse(t *testing.T, msg string, minIdealChunkPercentage float64) {
	header := HeaderSectionOnly(msg)
	body := CutHeaderSection(msg)
	if !isChunked(header) {
		RequireUnchunkedOHTTPMessage(t, unchunkedResponseOHTTPOverhead, header, body)
		return
	}
	// chunks are HTTP chunks on the body of the OHTTP message.
	chunks, err := ParseBodyChunks(body)
	require.NoError(t, err)

	RequireApproximateOHTTPResponseChunkLengths(t, chunks, minIdealChunkPercentage)
}

func RequireUnchunkedOHTTPMessage(t *testing.T, ohttpOverhead int, header, body string) {
	require.Contains(t, header, "Content-Length: "+strconv.Itoa(len(body)))
	ciphertextLen := len(body) - ohttpOverhead
	// should be a multiple of the inner chunk length because of BHTTP padding.
	require.Equal(t, 0, ciphertextLen%innerChunkLen)
}

// RequireExactOHTTPRequestChunkLengths verifies the chunk lengths of requests exactly. Since
// we're sending these, we have full control over them and can match them exactly.
func RequireExactOHTTPRequestChunkLengths(t *testing.T, chunks [][]byte) {
	// header, at least one body chunk, footer chunk.
	minChunks := 3

	require.GreaterOrEqual(t, len(chunks), minChunks)

	// verify the header chunk.
	require.Len(t, chunks[0], chunkedRequestOHTTPHeader)

	// verify the body chunks.
	for i := 1; i < len(chunks)-2; i++ {
		require.Len(t, chunks[i], idealOHTTPBodyChunk)
	}

	// verify the footer chunk.
	//nolint:gosec -- it's fine, these cipher lengths will be small-ish.
	footerChunkLen := quicvarint.Len(0) + int(aeadID.CipherLen(0))
	require.Len(t, chunks[len(chunks)-1], footerChunkLen)
}

// RequireApproximateOHTTPResponseChunkLengths verifies the chunk lengths of a response in fuzzy way. Since we
// don't control the exact chunk boundaries returned by the OHTTP relay we can't verify these exactly.
func RequireApproximateOHTTPResponseChunkLengths(t *testing.T, chunks [][]byte, minIdealChunkPercent float64) {
	totalLen := int64(0)
	gotIdealChunks := 0
	for _, chunk := range chunks {
		totalLen += int64(len(chunk))
		if len(chunk) == idealOHTTPBodyChunk {
			gotIdealChunks++
		}
	}

	payloadLen := totalLen - int64(chunkedResponseOHTTPHeader) - int64(emptyFooterChunkLen)
	require.Equal(t, int64(0), payloadLen%int64(idealOHTTPBodyChunk))

	wantedIdealChunks := payloadLen / int64(idealOHTTPBodyChunk)

	percentage := float64(gotIdealChunks) / float64(wantedIdealChunks) * 100.0
	require.GreaterOrEqual(t, percentage, minIdealChunkPercent)
}

func isChunked(header string) bool {
	return strings.Contains(header, "Transfer-Encoding: chunked") ||
		strings.Contains(header, "transfer-encoding: chunked")
}
