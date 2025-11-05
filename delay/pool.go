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

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Pool receives items and only makes them available after a specific amount of
// time has passed.
type Pool[T any] struct {
	mu       sync.Mutex
	heap     *poolHeap[T]
	capacity int

	// output returns the delayed items once they are ready.
	output chan Delayed[T]

	// closeCtx and cancel are used to control the lifetime
	closeCtx       context.Context
	closeCtxCancel context.CancelFunc
	closed         bool

	wg sync.WaitGroup
	// notifyNewItem is used to notify the processor when new items have been added
	// and the waiting time needs to be recalculated.
	notifyNewItem chan struct{}
	// notifySpaceAvailable is used to notify blocking Add calls that space has become available.
	notifySpaceAvailable chan struct{}
}

// NewPool creates a new delay pool. When capacity is non-zero the delay pool
// can contain at most that number of values. Calls to Add or AddWithDelayUpTo
// will block until values are taken out of the delay pool via Output.
func NewPool[T any](capacity int) *Pool[T] {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &Pool[T]{
		heap:                 &poolHeap[T]{},
		output:               make(chan Delayed[T]),
		capacity:             capacity,
		closeCtx:             ctx,
		closeCtxCancel:       cancel,
		notifyNewItem:        make(chan struct{}, 1), // buffered to prevent blocking
		notifySpaceAvailable: make(chan struct{}, 1), // buffered to prevent blocking
	}

	heap.Init(pool.heap)
	// start the background processor
	pool.wg.Add(1)
	go pool.processor()

	return pool
}

func (p *Pool[T]) AddWithDelayUpTo(ctx context.Context, v T, maxDelay time.Duration) error {
	dur, err := randDuration(maxDelay)
	if err != nil {
		return err
	}

	return p.Add(ctx, v, dur)
}

func (p *Pool[T]) Add(ctx context.Context, v T, delay time.Duration) error {
	item := &poolItem[T]{
		val:            v,
		delay:          delay,
		availableAfter: time.Now().Add(delay),
	}

	// loop until one of the following is true:
	// - the item is successfully added.
	// - delay pool is closed.
	// - user context is cancelled.
	for {
		added, err := p.tryAdd(item)
		if err != nil {
			return err
		}

		if added {
			// successfully added the item.
			return nil
		}

		select {
		case <-p.notifySpaceAvailable:
			// space might be available, try to add again.
			continue
		case <-p.closeCtx.Done():
			// pool was closed.
			return errors.New("cannot add item to closed pool")
		case <-ctx.Done():
			// user context was cancelled.
			return ctx.Err()
		}
	}
}

// tryAdd acquires the lock, checks if the item can be added. Return value
// indicate whether the item was added successfully. An error is returned when the
// delay pool is closed.
func (p *Pool[T]) tryAdd(item *poolItem[T]) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return false, errors.New("cannot add item to closed pool")
	}

	if p.capacity > 0 && p.heap.Len() >= p.capacity {
		// pool is at capacity.
		return false, nil
	}

	wasEmpty := p.heap.Len() == 0
	heap.Push(p.heap, item)

	// if this item is now the earliest item, we need to reset the timer.
	isEarliest := (*p.heap)[0] == item

	if wasEmpty || isEarliest {
		// non blocking notify
		select {
		case p.notifyNewItem <- struct{}{}:
		default:
		}
	}

	return true, nil
}

// Output returns the channel from which delayed items can be received.
func (p *Pool[T]) Output() <-chan Delayed[T] {
	return p.output
}

// Close stops the pool and closes the output channel. This method respects the delays
// on any items and blocks until all remaining items from the output channel have been consumed.
func (p *Pool[T]) Close() {
	ok := p.firstClose()
	if !ok {
		return
	}

	p.drainAndClose(true)
}

// CloseImmediate stops the pool and closes the output channel, this methods drains
// the output channel without regard for delays. Any remaining items are returned by
// this call.
func (p *Pool[T]) CloseImmediate() []T {
	ok := p.firstClose()
	if !ok {
		return nil
	}

	remaining := make(chan []T)
	go func() {
		var items []T
		for item := range p.Output() {
			items = append(items, item.V)
		}
		remaining <- items
	}()

	p.drainAndClose(false)
	return <-remaining
}

func (p *Pool[T]) firstClose() bool {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return false // Already closed
	}
	p.closed = true
	p.mu.Unlock()
	return true
}

func (p *Pool[T]) drainAndClose(respectDelays bool) {
	p.closeCtxCancel()
	p.wg.Wait()

	// drain any remaining items from the heap (respects their delays)
	p.drainHeap(respectDelays)

	close(p.output)
}

func (p *Pool[T]) processor() {
	defer p.wg.Done()

	timer := time.NewTimer(0)
	// stop the initial timer and drain its channel.
	if !timer.Stop() {
		<-timer.C
	}

	for {
		var nextTime time.Time
		var hasItems bool

		p.mu.Lock()
		if p.heap.Len() > 0 {
			nextTime = (*p.heap)[0].availableAfter
			hasItems = true
		}
		p.mu.Unlock()

		if !hasItems {
			// no items, wait for notification
			select {
			case <-p.closeCtx.Done():
				// Close was called, stop processing.
				return
			case <-p.notifyNewItem:
				// received a notification that an item was added,
				// process items again.
				continue
			}
		}

		// we have an item, wait until its ready
		now := time.Now()
		if nextTime.Before(now) || nextTime.Equal(now) {
			// item is ready now.
			p.processReadyItems()
			continue
		}

		// wait until the next item is ready.
		waitFor := nextTime.Sub(now)
		timer.Reset(waitFor)

		select {
		case <-p.closeCtx.Done():
			// Close was called, stop processing.
			timer.Stop()
			return
		case <-timer.C:
			// timer has expired, process ready items.
			p.processReadyItems()
		case <-p.notifyNewItem:
			// new item was added, may need to adjust timing.
			timer.Stop()
			// drain the timer channel if needed
			select {
			case <-timer.C:
			default:
			}
			continue
		}
	}
}

func (p *Pool[T]) processReadyItems() {
	now := time.Now()

	processed := 0
	for {
		p.mu.Lock()

		if p.heap.Len() == 0 {
			p.mu.Unlock()
			break
		}

		// peek at the top item
		topItem := (*p.heap)[0]

		if topItem.availableAfter.After(now) {
			// item not available yet, stop.
			p.mu.Unlock()
			break
		}

		// remove the item from the heap.
		readyItem, ok := p.popFromHeap()
		if !ok {
			// shouldn't happen since we checked length > 0 before,
			// but handle it graciously.
			p.mu.Unlock()
			continue
		}

		processed++
		p.mu.Unlock()

		// Send to output, which may block if the channel is full.
		select {
		case p.output <- Delayed[T]{
			Delay: readyItem.delay,
			V:     readyItem.val,
		}:
			// send the item, continue to a potential next one.
		case <-p.closeCtx.Done():
			return
		}
	}

	// if this pool has limited capacity, signal that space is available.
	if p.capacity > 0 && processed > 0 {
		// nonblocking notify.
		select {
		case p.notifySpaceAvailable <- struct{}{}:
		default:
		}
	}
}

func (p *Pool[T]) drainHeap(respectDelays bool) {
	for {
		p.mu.Lock()
		if p.heap.Len() == 0 {
			p.mu.Unlock()
			return
		}

		// get the the earliest item
		nextItem := (*p.heap)[0]

		if respectDelays {
			now := time.Now()
			if nextItem.availableAfter.After(now) {
				// item is not yet ready, wait for it
				waitFor := nextItem.availableAfter.Sub(now)
				p.mu.Unlock()

				time.Sleep(waitFor)
				continue
			}
		}

		// Item is ready, remove it from the heap.
		item, ok := p.popFromHeap()
		p.mu.Unlock()
		if !ok {
			// shouldn't happen since we checked length > 0 before,
			// but handle it graciously.
			continue
		}

		// send to output
		p.output <- Delayed[T]{
			Delay: item.delay,
			V:     item.val,
		}
	}
}

func (p *Pool[T]) popFromHeap() (*poolItem[T], bool) {
	if p.heap.Len() == 0 {
		return nil, false
	}
	val := heap.Pop(p.heap)
	item, ok := val.(*poolItem[T])
	if !ok {
		// Type assertion only required because container/heap is pre-generics
		// and works with the empty interface.
		//
		// We're not expecting anything else than asserted type here, but on the off
		// chance it does happen, we log an error message so users can tell us about
		// the bug.
		err := fmt.Errorf("received non *poolItem[T]: %v", val)
		slog.Error("popped invalid pool item", "error", err)
		return nil, false
	}
	return item, true
}
