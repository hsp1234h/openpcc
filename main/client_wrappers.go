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

// Functions in this file are Go wrappers around the exported C API functions. They do
// not constitute part of the public API of the library, and only exist to facilitate
// testing, since Go does not allow the use of CGO in test files.

package main

/*
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/openpcc/openpcc/anonpay/wallet"
)

// ClientCreate is a simple Go wrapper for Confsec_ClientCreate
func ClientCreate(
	apiKey string,
	concurrentRequestsTarget int,
	maxCandidateNodes int,
	defaultNodeTags []string,
	env string,
) (uintptr, error) {
	var errStr *C.char

	var nodeTags **C.char
	if len(defaultNodeTags) > 0 {
		nodeTags = goStrSliceToCStrArray(defaultNodeTags)
		defer freeCStrArray(nodeTags, C.size_t(len(defaultNodeTags)))
	}

	var envStr *C.char
	if env != "" {
		envStr = C.CString(env)
	}

	clientID := Confsec_ClientCreate(
		C.CString(apiKey),
		C.int(concurrentRequestsTarget),
		C.int(maxCandidateNodes),
		nodeTags,
		C.size_t(len(defaultNodeTags)),
		envStr,
		&errStr,
	)

	if errStr != nil {
		err := fmt.Errorf("failed to create client: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return 0, err
	}

	return uintptr(clientID), nil
}

// ClientDestroy is a simple Go wrapper for Confsec_ClientDestroy
func ClientDestroy(handle uintptr) error {
	var errStr *C.char

	Confsec_ClientDestroy(C.uintptr_t(handle), &errStr)

	if errStr != nil {
		err := fmt.Errorf("failed to destroy client: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return err
	}

	return nil
}

// ClientGetDefaultCreditAmountPerRequest is a simple Go wrapper for Confsec_ClientGetDefaultCreditAmountPerRequest
func ClientGetDefaultCreditAmountPerRequest(handle uintptr) (int64, error) {
	var errStr *C.char

	creditAmount := Confsec_ClientGetDefaultCreditAmountPerRequest(C.uintptr_t(handle), &errStr)

	if errStr != nil {
		err := fmt.Errorf("failed to get default credit amount per request: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return 0, err
	}

	return int64(creditAmount), nil
}

// ClientGetMaxCandidateNodes is a simple Go wrapper for Confsec_ClientGetMaxCandidateNodes
func ClientGetMaxCandidateNodes(handle uintptr) (int, error) {
	var errStr *C.char

	maxCandidateNodes := Confsec_ClientGetMaxCandidateNodes(C.uintptr_t(handle), &errStr)

	if errStr != nil {
		err := fmt.Errorf("failed to get max candidate nodes: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return 0, err
	}

	return int(maxCandidateNodes), nil
}

// ClientGetDefaultNodeTags is a simple Go wrapper for Confsec_ClientGetDefaultNodeTags
func ClientGetDefaultNodeTags(handle uintptr) ([]string, error) {
	var errStr *C.char
	var numTags C.size_t

	nodeTags := Confsec_ClientGetDefaultNodeTags(C.uintptr_t(handle), &numTags, &errStr)

	if errStr != nil {
		err := fmt.Errorf("failed to get default node tags: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return nil, err
	}

	return cStrArrayToGoStrSlice(nodeTags, numTags), nil
}

// ClientSetDefaultNodeTags is a simple Go wrapper for Confsec_ClientSetDefaultNodeTags
func ClientSetDefaultNodeTags(handle uintptr, defaultNodeTags []string) error {
	var errStr *C.char

	var nodeTags **C.char
	if len(defaultNodeTags) > 0 {
		nodeTags = goStrSliceToCStrArray(defaultNodeTags)
		defer freeCStrArray(nodeTags, C.size_t(len(defaultNodeTags)))
	}

	Confsec_ClientSetDefaultNodeTags(C.uintptr_t(handle), nodeTags, C.size_t(len(defaultNodeTags)), &errStr)

	if errStr != nil {
		err := fmt.Errorf("failed to set default node tags: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return err
	}

	return nil
}

// ClientGetWalletStatus is a simple Go wrapper for Confsec_ClientGetWalletStatus
func ClientGetWalletStatus(handle uintptr) (wallet.Status, error) {
	var errStr *C.char
	var walletStatus wallet.Status
	result := Confsec_ClientGetWalletStatus(C.uintptr_t(handle), &errStr)
	if result != nil {
		defer C.free(unsafe.Pointer(result))
	}

	if errStr != nil {
		err := fmt.Errorf("failed to get wallet status: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return walletStatus, err
	}

	walletStatusJSON := C.GoString(result)
	err := json.Unmarshal([]byte(walletStatusJSON), &walletStatus)
	if err != nil {
		return walletStatus, err
	}

	return walletStatus, nil
}

func ClientDoRequest(handle uintptr, req []byte) (uintptr, error) {
	var errStr *C.char

	reqBytes := C.CString(string(req))
	defer C.free(unsafe.Pointer(reqBytes))

	reqID := Confsec_ClientDoRequest(C.uintptr_t(handle), reqBytes, C.size_t(len(req)), &errStr)
	if errStr != nil {
		err := fmt.Errorf("failed to do request: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return 0, err
	}

	return uintptr(reqID), nil
}
