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

// Common functions needed by exported C API functions for C interop.

package main

/*
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

var (
	ErrNoAPIKey               = errors.New("missing API key")
	ErrInvalidEnv             = errors.New("invalid environment")
	ErrClientNotFound         = errors.New("client not found")
	ErrResponseNotFound       = errors.New("response not found")
	ErrResponseIsStreaming    = errors.New("response body is streaming")
	ErrResponseIsNotStreaming = errors.New("response body is not streaming")
	ErrResponseStreamNotFound = errors.New("response stream not found")
	ErrSerializationFailure   = errors.New("serialization failure")
)

// cStrArrayToGoStrSlice converts a C array of strings to a Go slice of strings.
func cStrArrayToGoStrSlice(arr **C.char, arrLen C.size_t) []string {
	if arr == nil || arrLen == 0 {
		return nil
	}
	slice := make([]string, arrLen)
	for i := range int(arrLen) {
		ptr := (**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(arr)) + uintptr(i)*unsafe.Sizeof(*arr)))
		slice[i] = C.GoString(*ptr)
	}
	return slice
}

// goStrSliceToCStrArray converts a Go slice of strings to a C array of strings.
func goStrSliceToCStrArray(slice []string) **C.char {
	if slice == nil {
		return nil
	}

	charPtrSize := unsafe.Sizeof(*(**C.char)(nil))
	arr := (**C.char)(C.malloc(C.size_t(charPtrSize * uintptr(len(slice)))))
	arrPtr := uintptr(unsafe.Pointer(arr))
	for i, s := range slice {
		*(**C.char)(unsafe.Pointer(arrPtr + uintptr(i)*charPtrSize)) = C.CString(s)
	}
	return arr
}

// freeCStrArray frees a C array of strings.
func freeCStrArray(arr **C.char, arrLen C.size_t) {
	if arr == nil || arrLen == 0 {
		return
	}
	for i := range int(arrLen) {
		ptr := (**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(arr)) + uintptr(i)*unsafe.Sizeof(*arr)))
		C.free(unsafe.Pointer(*ptr))
	}
	C.free(unsafe.Pointer(arr))
}

// setError sets the error string based on the given error.
func setError(errStr **C.char, err error) {
	*errStr = C.CString(err.Error())
}
