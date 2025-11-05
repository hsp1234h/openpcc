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
#include <stddef.h>
#include <stdint.h>
#include <string.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func ResponseStreamGetNext(handle uintptr) ([]byte, error) {
	var errStr *C.char

	chunk := Confsec_ResponseStreamGetNext(C.uintptr_t(handle), &errStr)
	if chunk != nil {
		defer C.free(unsafe.Pointer(chunk))
	}

	if errStr != nil {
		err := fmt.Errorf("failed to get streaming response chunk: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return nil, err
	}

	if chunk == nil {
		return nil, nil // End of stream
	}

	return []byte(C.GoString(chunk)), nil
}

func ResponseStreamDestroy(handle uintptr) error {
	var errStr *C.char

	Confsec_ResponseStreamDestroy(C.uintptr_t(handle), &errStr)

	if errStr != nil {
		err := fmt.Errorf("failed to destroy response stream: %s", C.GoString(errStr))
		C.free(unsafe.Pointer(errStr))
		return err
	}

	return nil
}
