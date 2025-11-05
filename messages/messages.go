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

package messages

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/confidentsecurity/bhttp"
	"github.com/confidentsecurity/twoway"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	MediaTypeRequest         = "application/confsec-req"
	MediaTypeRequestChunked  = "application/confsec-chunked-req"
	MediaTypeResponse        = "application/confsec-res"
	MediaTypeResponseChunked = "application/confsec-chunked-res"
)

const (
	UserChunkLen = 128
)

var (
	encodedChunkLen      = UserChunkLen + quicvarint.Len(UserChunkLen)
	encapsulatedChunkLen = encodedChunkLen + quicvarint.Len(UserChunkLen) + 16
)

var requestEncoder = &bhttp.RequestEncoder{
	MaxEncodedChunkLen: encodedChunkLen,
	PadToMultipleOf:    uint64(encodedChunkLen),
}
var requestDecoder = &bhttp.RequestDecoder{}

var responseEncoder = &bhttp.ResponseEncoder{
	MaxEncodedChunkLen: encodedChunkLen,
	PadToMultipleOf:    uint64(encodedChunkLen),
}
var responseDecoder = &bhttp.ResponseDecoder{}

var chunkedSealerOpts = []twoway.Option{
	twoway.EnableChunking(),
	twoway.WithMaxChunkPlaintextLen(encodedChunkLen),
}

var chunkedOpenerOpts = []twoway.Option{
	twoway.EnableChunking(),
	twoway.WithMaxChunkPlaintextLen(encodedChunkLen),
	twoway.WithInitialChunkBufferLen(encodedChunkLen),
}

// UnroutableHostname is the hostname that should be set on requests intended
// to be handled by the compute worker. The .invalid top-level domain is guaranteed
// not be routable and ensures that client doesn't accidentally forward private requests
// in case of a misconfiguration.
const UnroutableHostname = "confsec.invalid"

// IsRequestType indicates whether v is a known request type.
func IsRequestMediaType(v string) bool {
	return v == MediaTypeRequest || v == MediaTypeRequestChunked
}

func EncapsulatedChunkLen() int {
	return encapsulatedChunkLen
}

// EncapsulateRequest encapsulates req for the given sender. EncapsulateRequest returns the sealer and media type for
// the encapsulated request.
func EncapsulateRequest(snd *twoway.MultiRequestSender, req *http.Request) (*twoway.MultiRequestSealer, string, error) {
	reqMsg, err := requestEncoder.EncodeRequest(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode request to bhttp: %w", err)
	}

	var (
		mediaType = MediaTypeRequest
		opts      []twoway.Option
	)

	if reqMsg.IsIndeterminateLength() {
		mediaType = MediaTypeRequestChunked
		opts = chunkedSealerOpts
	}

	sealer, err := snd.NewRequestSealer(reqMsg, []byte(mediaType), opts...)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create new request sealer: %w", err)
	}

	return sealer, mediaType, nil
}

func DecapsulateRequest(ctx context.Context, rcv *twoway.MultiRequestReceiver, encapKey []byte, mediaType string, r io.Reader) (*http.Request, *twoway.RequestOpener, error) {
	var opts []twoway.Option
	switch mediaType {
	case MediaTypeRequest:
		// no options needed
	case MediaTypeRequestChunked:
		opts = chunkedOpenerOpts
	default:
		return nil, nil, errors.New("unknown media type")
	}

	opener, err := rcv.NewRequestOpener(encapKey, r, []byte(mediaType), opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request opener: %w", err)
	}

	req, err := requestDecoder.DecodeRequest(ctx, opener)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode request from bhttp: %w", err)
	}

	return req, opener, nil
}

// EncapsulateResponse encapsulates resp for the given sender. EncapsulateRequest returns the sealer and media type for
// the encapsulated response.
func EncapsulateResponse(rcv *twoway.RequestOpener, resp *http.Response) (*twoway.ResponseSealer, string, error) {
	respMsg, err := responseEncoder.EncodeResponse(resp)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode response to bhttp: %w", err)
	}

	var (
		mediaType = MediaTypeResponse
		opts      []twoway.Option
	)
	if respMsg.IsIndeterminateLength() {
		mediaType = MediaTypeResponseChunked
		opts = chunkedSealerOpts
	}

	sealer, err := rcv.NewResponseSealer(respMsg, []byte(mediaType), opts...)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create response sealer: %w", err)
	}

	return sealer, mediaType, nil
}

func DecapsulateResponse(ctx context.Context, openerFunc twoway.ResponseOpenerFunc, mediaType string, r io.Reader) (*http.Response, error) {
	var opts []twoway.Option
	switch mediaType {
	case MediaTypeResponse:
		// no options needed
	case MediaTypeResponseChunked:
		opts = chunkedOpenerOpts
	default:
		return nil, errors.New("unknown media type")
	}

	opener, err := openerFunc(r, []byte(mediaType), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create response opener: %w", err)
	}

	resp, err := responseDecoder.DecodeResponse(ctx, opener)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response from bhttp: %w", err)
	}

	return resp, nil
}
