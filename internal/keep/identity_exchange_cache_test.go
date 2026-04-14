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
	"testing"
	"time"
)

func TestIdentityExchangeCache_GetAdd(t *testing.T) {
	c := NewIdentityExchangeCache(10)

	if _, ok := c.Get("missing"); ok {
		t.Fatal("expected miss for unknown key")
	}

	c.Add("k1", "val1", time.Hour)
	got, ok := c.Get("k1")
	if !ok {
		t.Fatal("expected hit after Add")
	}
	if got != "val1" {
		t.Fatalf("got %q, want %q", got, "val1")
	}
}

func TestIdentityExchangeCache_TTLExpiry(t *testing.T) {
	c := NewIdentityExchangeCache(10)
	c.Add("k1", "val1", time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if _, ok := c.Get("k1"); ok {
		t.Fatal("expected expired entry to return miss")
	}
	if c.Len() != 0 {
		t.Fatalf("expected len 0 after expiry eviction, got %d", c.Len())
	}
}

func TestIdentityExchangeCache_LRUEviction(t *testing.T) {
	c := NewIdentityExchangeCache(3)
	c.Add("k1", "v1", time.Hour)
	c.Add("k2", "v2", time.Hour)
	c.Add("k3", "v3", time.Hour)

	// Access k1 to make it recently used; k2 is now the LRU.
	c.Get("k1")

	// Adding a fourth entry should evict the LRU (k2).
	c.Add("k4", "v4", time.Hour)

	if c.Len() != 3 {
		t.Fatalf("expected len 3, got %d", c.Len())
	}
	if _, ok := c.Get("k2"); ok {
		t.Fatal("expected k2 to be evicted")
	}
	for _, key := range []string{"k1", "k3", "k4"} {
		if _, ok := c.Get(key); !ok {
			t.Fatalf("expected key %q to still be present", key)
		}
	}
}

func TestIdentityExchangeCache_UpdateExisting(t *testing.T) {
	c := NewIdentityExchangeCache(10)
	c.Add("k1", "old", time.Hour)
	c.Add("k1", "new", time.Hour)
	got, ok := c.Get("k1")
	if !ok {
		t.Fatal("expected hit")
	}
	if got != "new" {
		t.Fatalf("got %q, want %q", got, "new")
	}
	if c.Len() != 1 {
		t.Fatalf("expected len 1 after update, got %d", c.Len())
	}
}

func TestIdentityExchangeCache_ZeroTTLNotCached(t *testing.T) {
	c := NewIdentityExchangeCache(10)
	c.Add("k1", "val", 0)
	if _, ok := c.Get("k1"); ok {
		t.Fatal("expected miss for zero-TTL entry")
	}
}
