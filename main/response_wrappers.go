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

package main

/*
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func ResponseDestroy(handle uintptr) error {
	var errStr *C.char

	Confsec_ResponseDestroy(C.uintptr_t(handle), &errStr)

	if errStr != nil {
		err := fmt.Errorf("failed to destroy response: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return err
	}

	return nil
}

func ResponseGetMetadata(handle uintptr) ([]byte, error) {
	var errStr *C.char

	metadata := Confsec_ResponseGetMetadata(C.uintptr_t(handle), &errStr)
	if metadata != nil {
		defer C.free(unsafe.Pointer(metadata))
	}

	if errStr != nil {
		err := fmt.Errorf("failed to get response metadata: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return nil, err
	}

	return []byte(C.GoString(metadata)), nil
}

func ResponseIsStreaming(handle uintptr) (bool, error) {
	var errStr *C.char

	isStreaming := Confsec_ResponseIsStreaming(C.uintptr_t(handle), &errStr)
	if errStr != nil {
		err := fmt.Errorf("failed to check if response is streaming: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return false, err
	}

	return isStreaming != C.bool(false), nil
}

func ResponseGetBody(handle uintptr) ([]byte, error) {
	var errStr *C.char

	body := Confsec_ResponseGetBody(C.uintptr_t(handle), &errStr)
	if body != nil {
		defer C.free(unsafe.Pointer(body))
	}

	if errStr != nil {
		err := fmt.Errorf("failed to get response body: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return nil, err
	}

	return []byte(C.GoString(body)), nil
}

func ResponseGetStream(handle uintptr) (uintptr, error) {
	var errStr *C.char

	stream := Confsec_ResponseGetStream(C.uintptr_t(handle), &errStr)

	if errStr != nil {
		err := fmt.Errorf("failed to get response stream: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return uintptr(0), err
	}

	return uintptr(stream), nil
}
