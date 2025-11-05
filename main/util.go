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
	"unsafe"
)

// Confsec_Free should be used by consumers of libconfsec to free heap-allocated memory
// returned by other libconfsec functions.
//
//export Confsec_Free
func Confsec_Free(ptr unsafe.Pointer) { //nolint:revive
	C.free(ptr)
}
