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

import "sync"

// registry is a simple thread-safe registry for generic objects, providing a mapping
// from a unique (per registry) identifier to the object.
// It is used to map opaque pointers returned via the C API to actual objects in Go.
type registry[T any] struct {
	mu     sync.RWMutex
	m      map[uintptr]*T
	nextID uintptr
}

// newRegistry creates a new registry.
func newRegistry[T any]() *registry[T] {
	return &registry[T]{
		m:      make(map[uintptr]*T),
		nextID: 1,
	}
}

// add adds a new object to the registry and returns its unique identifier.
func (r *registry[T]) add(v *T) uintptr {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := r.nextID
	r.m[id] = v
	r.nextID++
	return id
}

// get returns the object with the given identifier. If the object does not exist, nil
// is returned.
func (r *registry[T]) get(id uintptr) *T {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.m[id]
}

// remove removes the object with the given identifier from the registry. Removing an
// object that does not exist is a no-op.
func (r *registry[T]) remove(id uintptr) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.m, id)
}
