// Copyright 2026 Policy-as-Code Laboratories (PAC.Labs)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keep

import (
	"container/list"
	"sync"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// PrincipalCacher is the interface satisfied by any Principal cache backend.
// Implementations must be safe for concurrent use.
type PrincipalCacher interface {
	// Get returns a cached Principal and true if a valid (non-expired) entry exists.
	Get(key string) (shared.Principal, bool)
	// Add inserts or updates a Principal with the given TTL.
	Add(key string, principal shared.Principal, ttl time.Duration)
}

// PrincipalCache is a thread-safe LRU cache of normalized principals with TTL expiry.
// When the cache is at capacity, the least recently used entry is evicted.
type PrincipalCache struct {
	mu         sync.Mutex
	maxEntries int
	cache      map[string]*list.Element
	ll         *list.List
}

type principalEntry struct {
	key       string
	principal shared.Principal
	expiry    time.Time
}

// NewPrincipalCache returns a new PrincipalCache limited to maxEntries entries.
// maxEntries must be greater than zero.
func NewPrincipalCache(maxEntries int) *PrincipalCache {
	return &PrincipalCache{
		maxEntries: maxEntries,
		cache:      make(map[string]*list.Element),
		ll:         list.New(),
	}
}

// Get returns a cached Principal and true if a valid (non-expired) entry exists
// for key. Expired entries are removed and false is returned.
func (c *PrincipalCache) Get(key string) (shared.Principal, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ele, hit := c.cache[key]
	if !hit {
		return shared.Principal{}, false
	}
	e := ele.Value.(*principalEntry)
	if time.Now().After(e.expiry) {
		c.removeElement(ele)
		return shared.Principal{}, false
	}
	c.ll.MoveToFront(ele)
	return e.principal, true
}

// Add inserts or updates a Principal in the cache with the given TTL. If the
// cache is already at capacity, the least recently used entry is evicted first.
func (c *PrincipalCache) Add(key string, principal shared.Principal, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ele, hit := c.cache[key]; hit {
		c.ll.MoveToFront(ele)
		e := ele.Value.(*principalEntry)
		e.principal = principal
		e.expiry = time.Now().Add(ttl)
		return
	}
	ele := c.ll.PushFront(&principalEntry{
		key:       key,
		principal: principal,
		expiry:    time.Now().Add(ttl),
	})
	c.cache[key] = ele
	if c.ll.Len() > c.maxEntries {
		c.removeOldest()
	}
}

// Len returns the number of entries currently in the cache, including expired ones.
func (c *PrincipalCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

func (c *PrincipalCache) removeOldest() {
	if ele := c.ll.Back(); ele != nil {
		c.removeElement(ele)
	}
}

func (c *PrincipalCache) removeElement(ele *list.Element) {
	c.ll.Remove(ele)
	delete(c.cache, ele.Value.(*principalEntry).key)
}
