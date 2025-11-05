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

package work

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type Job interface {
	Process()
}

type JobFunc func()

func (jf JobFunc) Process() {
	jf()
}

type PoolConfig struct {
	QueueLen int
}

var ErrPoolClosed = errors.New("work pool is closed")

type Pool struct {
	mu *sync.Mutex
	wg *sync.WaitGroup

	closeCtx      context.Context
	cancelAddJobs context.CancelFunc

	// scaleDown sends signal to a worker to stop. Each value should stop 1 worker.
	scaleDown chan struct{}
	jobQueue  chan Job

	workers     *atomic.Int32
	idleWorkers *atomic.Int32
}

func NewPool(maxOpenJobs, startingWorkers int) *Pool {
	if startingWorkers < 1 {
		startingWorkers = 1
	}
	closeCtx, closeFunc := context.WithCancel(context.Background())
	p := &Pool{
		mu:            &sync.Mutex{},
		wg:            &sync.WaitGroup{},
		closeCtx:      closeCtx,
		cancelAddJobs: closeFunc,
		jobQueue:      make(chan Job, maxOpenJobs),
		scaleDown:     make(chan struct{}),
		workers:       &atomic.Int32{},
		idleWorkers:   &atomic.Int32{},
	}

	// begin with minimum nr of workers
	for range startingWorkers {
		p.startWorker()
	}

	return p
}

func (p *Pool) MaxOpenJobs() int {
	return cap(p.jobQueue)
}

func (p *Pool) OpenJobs() int {
	return len(p.jobQueue)
}

func (p *Pool) Workers() int {
	return int(p.workers.Load())
}

func (p *Pool) IdleWorkers() int {
	return int(p.idleWorkers.Load())
}

func (p *Pool) ScaleWorkers(totalWorkers int) error {
	if totalWorkers < 1 {
		return fmt.Errorf("needs at least one worker, got %d", totalWorkers)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.isClosed() {
		return ErrPoolClosed
	}

	diff := totalWorkers - int(p.workers.Load())
	if diff == 0 {
		return nil
	}
	for diff > 0 {
		p.startWorker()
		diff--
	}
	for diff < 0 {
		p.stopWorker()
		diff++
	}

	return nil
}

func (p *Pool) startWorker() {
	p.workers.Add(1)
	p.wg.Add(1)

	go func() {
		defer func() {
			p.wg.Done()
			p.workers.Add(-1)
		}()

		for {
			p.idleWorkers.Add(1)
			select {
			case <-p.scaleDown:
				// caught a scale down signal, stop.
				p.idleWorkers.Add(-1)
				return
			case j, ok := <-p.jobQueue:
				if !ok {
					// job queue closed, pool has been closed.
					return
				}
				p.idleWorkers.Add(-1)
				j.Process()
			}
		}
	}()
}

func (p *Pool) stopWorker() {
	p.scaleDown <- struct{}{}
}

func (p *Pool) AddJob(ctx context.Context, j Job) error {
	if p.closeCtx.Err() != nil {
		return ErrPoolClosed
	}

	select {
	case <-p.closeCtx.Done():
		return ErrPoolClosed
	case p.jobQueue <- j:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Pool) isClosed() bool {
	return p.closeCtx.Err() != nil
}

func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.isClosed() {
		return
	}

	// signal to any open AddJobs that the work pool is closing.
	p.cancelAddJobs()

	// wait for all workers to become idle.
	for p.IdleWorkers() < p.Workers() {
		time.Sleep(5 * time.Millisecond)
	}

	// close the job queue to signals to the workers that they
	// should stop.
	close(p.jobQueue)

	// wait for all workers to exit.
	p.wg.Wait()
}
