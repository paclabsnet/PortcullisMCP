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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

func principal(id string) shared.Principal {
	return shared.Principal{UserID: id}
}

func TestPrincipalCache_GetMiss(t *testing.T) {
	c := NewPrincipalCache(10)
	if _, ok := c.Get("missing"); ok {
		t.Error("expected cache miss for absent key, got hit")
	}
}

func TestPrincipalCache_AddAndGet(t *testing.T) {
	c := NewPrincipalCache(10)
	c.Add("alice", principal("alice"), time.Minute)

	got, ok := c.Get("alice")
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}
	if got.UserID != "alice" {
		t.Errorf("UserID = %q, want alice", got.UserID)
	}
}

func TestPrincipalCache_UpdateExistingEntry(t *testing.T) {
	c := NewPrincipalCache(10)
	c.Add("alice", principal("alice-v1"), time.Minute)
	c.Add("alice", principal("alice-v2"), time.Minute)

	got, ok := c.Get("alice")
	if !ok {
		t.Fatal("expected cache hit after update, got miss")
	}
	if got.UserID != "alice-v2" {
		t.Errorf("UserID = %q, want alice-v2", got.UserID)
	}
}

func TestPrincipalCache_TTLExpiry(t *testing.T) {
	c := NewPrincipalCache(10)
	c.Add("alice", principal("alice"), -time.Millisecond) // already expired

	if _, ok := c.Get("alice"); ok {
		t.Error("expected cache miss for expired entry, got hit")
	}
	if c.Len() != 0 {
		t.Errorf("Len() = %d after expired Get, want 0 (expired entries are evicted on access)", c.Len())
	}
}

func TestPrincipalCache_LRUEviction(t *testing.T) {
	c := NewPrincipalCache(3)
	c.Add("a", principal("a"), time.Minute)
	c.Add("b", principal("b"), time.Minute)
	c.Add("c", principal("c"), time.Minute)

	// Touch "a" to make it most-recently-used; "b" becomes the LRU.
	_, _ = c.Get("a")

	// Adding a 4th entry should evict "b" (LRU).
	c.Add("d", principal("d"), time.Minute)

	if c.Len() != 3 {
		t.Errorf("Len() = %d, want 3 after eviction", c.Len())
	}
	if _, ok := c.Get("b"); ok {
		t.Error("expected 'b' to be evicted (LRU), but it was still present")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := c.Get(k); !ok {
			t.Errorf("expected %q to remain in cache after eviction, but it was absent", k)
		}
	}
}

func TestPrincipalCache_LRUEviction_OldestIsEvicted(t *testing.T) {
	c := NewPrincipalCache(2)
	c.Add("first", principal("first"), time.Minute)
	c.Add("second", principal("second"), time.Minute)
	// "first" was inserted first; without any access it is the LRU.
	c.Add("third", principal("third"), time.Minute)

	if _, ok := c.Get("first"); ok {
		t.Error("expected 'first' to be evicted as LRU, but it was still present")
	}
	if _, ok := c.Get("second"); !ok {
		t.Error("expected 'second' to remain, but it was absent")
	}
	if _, ok := c.Get("third"); !ok {
		t.Error("expected 'third' to remain, but it was absent")
	}
}

func TestPrincipalCache_Len(t *testing.T) {
	c := NewPrincipalCache(10)
	if c.Len() != 0 {
		t.Errorf("Len() = %d on empty cache, want 0", c.Len())
	}
	c.Add("a", principal("a"), time.Minute)
	c.Add("b", principal("b"), time.Minute)
	if c.Len() != 2 {
		t.Errorf("Len() = %d after two adds, want 2", c.Len())
	}
}

func TestPrincipalCache_ConcurrentAccess(t *testing.T) {
	c := NewPrincipalCache(50)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("user-%d", i)
			c.Add(key, principal(key), time.Minute)
			_, _ = c.Get(key)
		}(i)
	}
	wg.Wait()
}
