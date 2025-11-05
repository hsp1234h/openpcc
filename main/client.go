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

// C API functions related to CONFSEC client operations are defined in this file.

package main

/*
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
*/
import "C"

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"unsafe"

	"github.com/openpcc/openpcc"
	"github.com/openpcc/openpcc/transparency"
)

type GetOptsFn func() []openpcc.Option

const (
	stagingAPIURL = "https://app.stage.confident.security"
	prodAPIURL    = "https://app.confident.security"
)

var (
	// getOpts is a function that returns a slice of openpcc.Option objects used to
	// initialize a openpcc.Client. By default it is nil, but can be set e.g., during
	// testing to inject mock dependencies.
	getOpts GetOptsFn

	// clientsRegistry is a registry of openpcc.Client objects created by the caller
	// of the C API.
	clientsRegistry = newRegistry[openpcc.Client]()
)

// WithGetOpts is a helper function to temporarily set the getOpts function. This is
// intended for testing, so it's not exported, nor should it be accessible via any
// code path reachable with the C API.
func WithGetOpts(getOptsFn GetOptsFn, fn func()) {
	tmp := getOpts
	getOpts = getOptsFn
	defer func() {
		getOpts = tmp
	}()
	fn()
}

// Confsec_ClientCreate creates a new client, returning a handle to it.
//
//export Confsec_ClientCreate
func Confsec_ClientCreate( //nolint:revive
	apiURL *C.char,
	apiKey *C.char,
	identityPolicySource C.int,
	oidcIssuer *C.char,
	oidcIssuerRegex *C.char,
	oidcSubject *C.char,
	oidcSubjectRegex *C.char,
	concurrentRequestsTarget C.int,
	maxCandidateNodes C.int,
	defaultNodeTags **C.char,
	defaultNodeTagsCount C.size_t,
	env *C.char,
	errStr **C.char,
) C.uintptr_t {
	// Error early if no API URL is provided
	if apiURL == nil {
		setError(errStr, ErrNoAPIURL)
		return C.uintptr_t(0)
	}
	// Error early if no API key is provided
	if apiKey == nil {
		setError(errStr, ErrNoAPIKey)
		return C.uintptr_t(0)
	}
	// Error early if the identity policy source is invalid
	idPolicySource := openpcc.IdentityPolicySource(identityPolicySource)
	if idPolicySource != openpcc.IdentityPolicySourceConfigured &&
		idPolicySource != openpcc.IdentityPolicySourceUnsafeRemote {
		setError(errStr, ErrInvalidIdentityPolicySource)
		return C.uintptr_t(0)
	}

	// Determine environment from the env param, defaulting to prod
	var transparencyEnv transparency.Environment
	if env == nil {
		transparencyEnv = transparency.EnvironmentProd
	} else {
		transparencyEnv = transparency.Environment(C.GoString(env))
	}

	// Collect default node tags into a slice of strings
	nodeTags := cStrArrayToGoStrSlice(defaultNodeTags, defaultNodeTagsCount)

	config := openpcc.DefaultConfig()
	config.APIKey = C.GoString(apiKey)
	config.APIURL = C.GoString(apiURL)
	config.TransparencyVerifier.Environment = transparencyEnv
	config.TransparencyIdentityPolicySource = idPolicySource
	// Only set the identity policy if the source is 'configured'
	if idPolicySource == openpcc.IdentityPolicySourceConfigured {
		config.TransparencyIdentityPolicy = &transparency.IdentityPolicy{
			OIDCIssuer:       C.GoString(oidcIssuer),
			OIDCIssuerRegex:  C.GoString(oidcIssuerRegex),
			OIDCSubject:      C.GoString(oidcSubject),
			OIDCSubjectRegex: C.GoString(oidcSubjectRegex),
		}
	} else {
		config.TransparencyIdentityPolicy = nil
	}
	// Treat 0 as "not set" for numeric config options
	if maxCandidateNodes > C.int(0) {
		config.MaxCandidateNodes = int(maxCandidateNodes)
	}
	if concurrentRequestsTarget > C.int(0) {
		config.ConcurrentRequestsTarget = int(concurrentRequestsTarget)
	}
	// Only set default node tags if there were given
	if defaultNodeTagsCount > 0 {
		config.DefaultRequestParams.NodeTags = nodeTags
	}

	var opts []openpcc.Option
	if getOpts != nil {
		opts = getOpts()
	}

	client, err := openpcc.NewFromConfig(context.Background(), config, opts...)
	if err != nil {
		setError(errStr, err)
		return C.uintptr_t(0)
	}

	// Register the created client and return its handle
	id := clientsRegistry.add(client)

	return C.uintptr_t(id)
}

// Confsec_ClientDestroy safely destroys the client associated with the given handle.
//
//export Confsec_ClientDestroy
func Confsec_ClientDestroy(handle C.uintptr_t, errStr **C.char) { //nolint:revive
	client := clientsRegistry.get(uintptr(handle))
	if client == nil {
		setError(errStr, ErrClientNotFound)
		return
	}

	err := client.Close(context.Background())
	if err != nil {
		setError(errStr, err)
		return
	}

	clientsRegistry.remove(uintptr(handle))
}

// Confsec_ClientGetDefaultCreditAmountPerRequest returns the currently configured
// default credit amount sent per request for the client associated with the given
// handle.
//
//export Confsec_ClientGetDefaultCreditAmountPerRequest
func Confsec_ClientGetDefaultCreditAmountPerRequest(handle C.uintptr_t, errStr **C.char) C.long { //nolint:revive
	client := clientsRegistry.get(uintptr(handle))
	if client == nil {
		setError(errStr, ErrClientNotFound)
		return C.long(0)
	}

	return C.long(client.DefaultRequestParams().CreditAmount)
}

// Confsec_ClientGetMaxCandidateNodes returns the currently configured maximum number
// of candidate compute nodes targeted per request for the client associated with the
// given handle.
//
//export Confsec_ClientGetMaxCandidateNodes
func Confsec_ClientGetMaxCandidateNodes(handle C.uintptr_t, errStr **C.char) C.int { //nolint:revive
	client := clientsRegistry.get(uintptr(handle))
	if client == nil {
		setError(errStr, ErrClientNotFound)
		return C.int(0)
	}

	return C.int(client.GetMaxCandidateNodes())
}

// Confsec_ClientGetDefaultNodeTags returns the currently configured default node tags
// for the client associated with the given handle.
//
//export Confsec_ClientGetDefaultNodeTags
func Confsec_ClientGetDefaultNodeTags(handle C.uintptr_t, defaultNodeTagsCount *C.size_t, errStr **C.char) **C.char { //nolint:revive
	client := clientsRegistry.get(uintptr(handle))
	if client == nil {
		setError(errStr, ErrClientNotFound)
		return nil
	}

	nodeTags := client.DefaultRequestParams().NodeTags
	*defaultNodeTagsCount = C.size_t(len(nodeTags))

	return goStrSliceToCStrArray(client.DefaultRequestParams().NodeTags)
}

// Confsec_ClientSetDefaultNodeTags sets the default node tags for the client associated
// with the given handle.
//
//export Confsec_ClientSetDefaultNodeTags
func Confsec_ClientSetDefaultNodeTags(handle C.uintptr_t, defaultNodeTags **C.char, defaultNodeTagsCount C.size_t, errStr **C.char) { //nolint:revive
	client := clientsRegistry.get(uintptr(handle))
	if client == nil {
		setError(errStr, ErrClientNotFound)
		return
	}

	nodeTags := cStrArrayToGoStrSlice(defaultNodeTags, defaultNodeTagsCount)
	err := client.SetDefaultNodeTags(nodeTags)
	if err != nil {
		setError(errStr, err)
		return
	}
}

// Confsec_ClientGetWalletStatus returns the current wallet status for the client
// associated with the given handle. The returned value is a stringified JSON object.
//
//export Confsec_ClientGetWalletStatus
func Confsec_ClientGetWalletStatus(handle C.uintptr_t, errStr **C.char) *C.char { //nolint:revive
	client := clientsRegistry.get(uintptr(handle))
	if client == nil {
		setError(errStr, ErrClientNotFound)
		return nil
	}

	walletStatus := client.WalletStatus()
	walletStatusJSON, err := json.Marshal(walletStatus)
	if err != nil {
		setError(errStr, ErrSerializationFailure)
		return nil
	}

	return C.CString(string(walletStatusJSON))
}

// Confsec_ClientDoRequest sends a request to the Confident Security network via the
// client associated with the given handle. The request argument should be the raw
// HTTP request including start line, headers, and body.
//
//export Confsec_ClientDoRequest
func Confsec_ClientDoRequest(handle C.uintptr_t, request *C.char, requestLength C.size_t, errStr **C.char) C.uintptr_t { //nolint:revive
	client := clientsRegistry.get(uintptr(handle))
	if client == nil {
		setError(errStr, ErrClientNotFound)
		return C.uintptr_t(0)
	}

	// Parse the raw request into an http.Request
	reqBytes := C.GoBytes(unsafe.Pointer(request), C.int(requestLength))
	reqReader := bufio.NewReader(bytes.NewReader(reqBytes))
	req, err := http.ReadRequest(reqReader)
	if err != nil {
		setError(errStr, err)
		return C.uintptr_t(0)
	}

	// http.ReadRequest only parses the path, not the full URL
	// Reconstruct the full URL from the Host header
	if req.URL.Scheme == "" {
		if req.TLS != nil {
			req.URL.Scheme = "https"
		} else {
			req.URL.Scheme = "http"
		}
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	// Send the request and get the response
	resp, err := client.RoundTrip(req)
	if err != nil {
		setError(errStr, err)
		return C.uintptr_t(0)
	}

	// Register the response and return its handle
	r := &response{resp: resp}
	id := responsesRegistry.add(r)

	return C.uintptr_t(id)
}
