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
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
	identity "github.com/paclabsnet/PortcullisMCP/internal/shared/identity"
)

// newTestRedisCache starts a miniredis server and returns a RedisPrincipalCache
// backed by it. The server is closed automatically when the test ends.
func newTestRedisCache(t *testing.T) (*RedisPrincipalCache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewRedisPrincipalCache(client, ""), mr
}

func TestRedisPrincipalCache_GetMiss(t *testing.T) {
	c, _ := newTestRedisCache(t)
	if _, ok := c.Get("missing"); ok {
		t.Error("expected cache miss for absent key, got hit")
	}
}

func TestRedisPrincipalCache_AddAndGet(t *testing.T) {
	c, _ := newTestRedisCache(t)
	p := shared.Principal{UserID: "alice", Email: "alice@corp.com"}
	c.Add("alice-key", p, time.Minute)

	got, ok := c.Get("alice-key")
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}
	if got.UserID != p.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, p.UserID)
	}
	if got.Email != p.Email {
		t.Errorf("Email = %q, want %q", got.Email, p.Email)
	}
}

func TestRedisPrincipalCache_TTLExpiry(t *testing.T) {
	c, mr := newTestRedisCache(t)
	c.Add("alice-key", shared.Principal{UserID: "alice"}, 2*time.Second)

	// Confirm it's present before expiry.
	if _, ok := c.Get("alice-key"); !ok {
		t.Fatal("expected cache hit before TTL expires, got miss")
	}

	// Fast-forward miniredis clock past the TTL.
	mr.FastForward(3 * time.Second)

	if _, ok := c.Get("alice-key"); ok {
		t.Error("expected cache miss after TTL expires, got hit")
	}
}

func TestRedisPrincipalCache_ZeroTTL_NotStored(t *testing.T) {
	c, _ := newTestRedisCache(t)
	c.Add("alice-key", shared.Principal{UserID: "alice"}, 0)

	if _, ok := c.Get("alice-key"); ok {
		t.Error("expected no storage for zero TTL, got cache hit")
	}
}

func TestRedisPrincipalCache_UpdateExistingEntry(t *testing.T) {
	c, _ := newTestRedisCache(t)
	c.Add("key", shared.Principal{UserID: "v1"}, time.Minute)
	c.Add("key", shared.Principal{UserID: "v2"}, time.Minute)

	got, ok := c.Get("key")
	if !ok {
		t.Fatal("expected cache hit after update, got miss")
	}
	if got.UserID != "v2" {
		t.Errorf("UserID = %q, want v2", got.UserID)
	}
}

func TestRedisPrincipalCache_KeyIsolation(t *testing.T) {
	c, _ := newTestRedisCache(t)
	c.Add("key-a", shared.Principal{UserID: "alice"}, time.Minute)
	c.Add("key-b", shared.Principal{UserID: "bob"}, time.Minute)

	a, _ := c.Get("key-a")
	b, _ := c.Get("key-b")
	if a.UserID != "alice" {
		t.Errorf("key-a: UserID = %q, want alice", a.UserID)
	}
	if b.UserID != "bob" {
		t.Errorf("key-b: UserID = %q, want bob", b.UserID)
	}
}

func TestRedisPrincipalCache_DefaultKeyPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	c := NewRedisPrincipalCache(client, "")

	c.Add("mykey", shared.Principal{UserID: "alice"}, time.Minute)

	// Verify the key is stored under the expected prefix.
	keys := mr.Keys()
	found := false
	for _, k := range keys {
		if k == defaultKeepKeyPrefix+"mykey" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected key %q in Redis, got keys: %v", defaultKeepKeyPrefix+"mykey", keys)
	}
}

func TestRedisPrincipalCache_CustomKeyPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	c := NewRedisPrincipalCache(client, "custom:prefix:")

	c.Add("mykey", shared.Principal{UserID: "alice"}, time.Minute)

	keys := mr.Keys()
	found := false
	for _, k := range keys {
		if k == "custom:prefix:mykey" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected key with custom prefix in Redis, got keys: %v", keys)
	}
}

func TestRedisPrincipalCache_GetReturnsAllPrincipalFields(t *testing.T) {
	c, _ := newTestRedisCache(t)
	want := shared.Principal{
		UserID:      "alice",
		Email:       "alice@corp.com",
		DisplayName: "Alice Admin",
		Groups:      []string{"admins", "developers"},
		Department:  "Engineering",
		SourceType:  "oidc",
	}
	c.Add("key", want, time.Minute)

	got, ok := c.Get("key")
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}
	if got.UserID != want.UserID || got.Email != want.Email || got.DisplayName != want.DisplayName ||
		got.Department != want.Department || got.SourceType != want.SourceType {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if len(got.Groups) != len(want.Groups) || got.Groups[0] != want.Groups[0] {
		t.Errorf("Groups = %v, want %v", got.Groups, want.Groups)
	}
}

// TestBuildPrincipalCache_MemoryBackend verifies the in-process cache is returned
// for the "memory" and "" backends.
func TestBuildPrincipalCache_MemoryBackend(t *testing.T) {
	for _, backend := range []string{"memory", ""} {
		t.Run("backend="+backend, func(t *testing.T) {
			storage := cfgloader.StorageConfig{Backend: backend}
			cache, err := buildPrincipalCache(context.Background(), storage, identity.NormalizerConfig{CacheMaxEntries: 50})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if _, ok := cache.(*PrincipalCache); !ok {
				t.Errorf("expected *PrincipalCache, got %T", cache)
			}
		})
	}
}

func TestBuildPrincipalCache_MemoryBackend_DefaultMaxEntries(t *testing.T) {
	storage := cfgloader.StorageConfig{Backend: "memory"}
	cache, err := buildPrincipalCache(context.Background(), storage, identity.NormalizerConfig{CacheMaxEntries: 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should not panic or error — just use the default of 1000.
	pc, ok := cache.(*PrincipalCache)
	if !ok {
		t.Fatalf("expected *PrincipalCache, got %T", cache)
	}
	if pc.maxEntries != 1000 {
		t.Errorf("maxEntries = %d, want 1000 (default)", pc.maxEntries)
	}
}

func TestBuildPrincipalCache_RedisBackend(t *testing.T) {
	mr := miniredis.RunT(t)
	storage := cfgloader.StorageConfig{
		Backend: "redis",
		Config:  map[string]any{"addr": mr.Addr()},
	}
	cache, err := buildPrincipalCache(context.Background(), storage, identity.NormalizerConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := cache.(*RedisPrincipalCache); !ok {
		t.Errorf("expected *RedisPrincipalCache, got %T", cache)
	}
}

func TestBuildPrincipalCache_UnknownBackend_ReturnsError(t *testing.T) {
	storage := cfgloader.StorageConfig{Backend: "memcached"}
	_, err := buildPrincipalCache(context.Background(), storage, identity.NormalizerConfig{})
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}
}
