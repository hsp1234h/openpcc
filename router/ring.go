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

package router

import (
	"cmp"
	"encoding/binary"
	"hash/crc32"
	"maps"
	"net/url"
	"slices"
	"sync"

	"github.com/google/uuid"
)

const virtualNodesPerRouter = 100

type ring struct {
	mu          sync.RWMutex
	routers     map[uuid.UUID]struct{}
	posToRouter map[uint32]uuid.UUID
	positions   []uint32
}

func newRing() *ring {
	return &ring{
		mu:          sync.RWMutex{},
		routers:     make(map[uuid.UUID]struct{}),
		posToRouter: make(map[uint32]uuid.UUID),
		positions:   []uint32{},
	}
}

func (r *ring) addRouter(routerID uuid.UUID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, ok := r.routers[routerID]
	if ok {
		return
	}

	r.routers[routerID] = struct{}{}

	// add virtual nodes for the router
	data := append(make([]byte, 4), routerID[:]...)
	for i := uint32(0); i < virtualNodesPerRouter; i++ {
		binary.BigEndian.PutUint32(data[0:4], i)
		pos := crc32.ChecksumIEEE(data)

		r.posToRouter[pos] = routerID
		r.positions = append(r.positions, pos)
	}

	slices.Sort(r.positions)
}

func (r *ring) removeRouter(routerID uuid.UUID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, ok := r.routers[routerID]
	if !ok {
		return
	}

	newPositions := make([]uint32, 0, len(r.positions))
	for _, pos := range r.positions {
		if r.posToRouter[pos] != routerID {
			newPositions = append(newPositions, pos)
		} else {
			delete(r.posToRouter, pos)
		}
	}

	delete(r.routers, routerID)

	r.positions = newPositions
}

type nodePosition struct {
	nodeID   uuid.UUID
	position uint32
}

// queryHealthcheckURLs finds the urls of the nodes for whicht the given router is responsible.
func (r *ring) queryHealthcheckURLs(routerID uuid.UUID, nodes map[uuid.UUID]url.URL) map[uuid.UUID]url.URL {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.positions) == 0 || len(nodes) == 0 {
		return nil
	}

	// create and hash positions for nodes
	nodePositions := make([]nodePosition, 0, len(nodes))
	for id := range nodes {
		nodePositions = append(nodePositions, nodePosition{
			nodeID:   id,
			position: crc32.ChecksumIEEE(id[:]),
		})
	}

	// sort nodes by position
	slices.SortFunc(nodePositions, func(a, b nodePosition) int {
		return cmp.Compare(a.position, b.position)
	})

	// find nodes for which the router is responsible
	out := make(map[uuid.UUID]url.URL)

	posIndex := 0
	for _, np := range nodePositions {
		if posIndex < len(r.positions) && r.positions[posIndex] < np.position {
			posIndex++
		}

		// wrap around at the end
		if posIndex == len(r.positions) {
			posIndex = 0
		}

		if r.posToRouter[r.positions[posIndex]] == routerID {
			out[np.nodeID] = nodes[np.nodeID]
		}
	}

	return out
}

func (r *ring) queryRouters() map[uuid.UUID]struct{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return maps.Clone(r.routers)
}

func (r *ring) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.routers)
}
