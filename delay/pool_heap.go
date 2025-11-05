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

package delay

import "time"

type poolItem[T any] struct {
	val            T
	delay          time.Duration
	availableAfter time.Time
	index          int
}

// poolHeap implements container/heap.Interface and orders items by
// their availableAfter timestamps (early -> old).
type poolHeap[T any] []*poolItem[T]

func (h poolHeap[T]) Len() int {
	return len(h)
}

func (h poolHeap[T]) Less(i, j int) bool {
	return h[i].availableAfter.Before(h[j].availableAfter)
}

func (h poolHeap[T]) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *poolHeap[T]) Push(x any) {
	item, ok := x.(*poolItem[T])
	if !ok {
		return
	}

	item.index = len(*h)
	*h = append(*h, item)
}

func (h *poolHeap[T]) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*h = old[0 : n-1]
	return item
}
