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

package gate

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRedisPendingStore(t *testing.T) (*RedisPendingStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })
	return NewRedisPendingStore(client, "test:"), mr
}

func TestRedisPendingStore_StoreGetDelete(t *testing.T) {
	store, _ := newTestRedisPendingStore(t)
	ctx := context.Background()

	p := pendingEscalation{
		ServerName: "backend",
		ToolName:   "restricted_op",
		JTI:        "jti-store-test",
		ExpiresAt:  time.Now().Add(time.Hour),
	}

	store.Store(ctx, "sess:abc:backend/restricted_op", p)

	got, ok := store.Get(ctx, "sess:abc:backend/restricted_op")
	if !ok {
		t.Fatal("Get: expected entry to be present")
	}
	if got.JTI != "jti-store-test" {
		t.Errorf("JTI = %q, want %q", got.JTI, "jti-store-test")
	}
	if got.ServerName != "backend" {
		t.Errorf("ServerName = %q, want %q", got.ServerName, "backend")
	}

	store.Delete(ctx, "sess:abc:backend/restricted_op")

	if _, ok := store.Get(ctx, "sess:abc:backend/restricted_op"); ok {
		t.Error("entry should be absent after Delete")
	}
}

func TestRedisPendingStore_GetMissing(t *testing.T) {
	store, _ := newTestRedisPendingStore(t)
	_, ok := store.Get(context.Background(), "nonexistent-key")
	if ok {
		t.Error("Get on missing key should return false")
	}
}

func TestRedisPendingStore_AlreadyExpiredIsNoop(t *testing.T) {
	store, _ := newTestRedisPendingStore(t)
	ctx := context.Background()

	p := pendingEscalation{
		JTI:       "jti-expired",
		ExpiresAt: time.Now().Add(-time.Second), // already expired
	}
	store.Store(ctx, "expired-key", p)

	// Store should have been a no-op — key must not exist.
	if _, ok := store.Get(ctx, "expired-key"); ok {
		t.Error("expired entry should not be stored")
	}
}

func TestRedisPendingStore_KeyFormat(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })

	store := NewRedisPendingStore(client, "myns:")

	ctx := context.Background()
	store.Store(ctx, "sess:user1:srv/tool", pendingEscalation{
		JTI:       "jti-key-format",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	// The raw Redis key must use the prefix + "pnd:" namespace.
	keys := mr.Keys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d: %v", len(keys), keys)
	}
	if keys[0] != "myns:pnd:sess:user1:srv/tool" {
		t.Errorf("key = %q, want %q", keys[0], "myns:pnd:sess:user1:srv/tool")
	}
}

func TestRedisPendingStore_DefaultPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })

	// Empty prefix should fall back to "portcullis:".
	store := NewRedisPendingStore(client, "")

	ctx := context.Background()
	store.Store(ctx, "k", pendingEscalation{JTI: "j", ExpiresAt: time.Now().Add(time.Hour)})

	keys := mr.Keys()
	if len(keys) != 1 || keys[0] != "portcullis:pnd:k" {
		t.Errorf("expected key %q, got %v", "portcullis:pnd:k", keys)
	}
}

func TestRedisPendingStore_TTLExpiry(t *testing.T) {
	store, mr := newTestRedisPendingStore(t)
	ctx := context.Background()

	store.Store(ctx, "ttl-key", pendingEscalation{
		JTI:       "jti-ttl",
		ExpiresAt: time.Now().Add(2 * time.Second),
	})

	if _, ok := store.Get(ctx, "ttl-key"); !ok {
		t.Fatal("entry should be present before TTL expiry")
	}

	mr.FastForward(3 * time.Second)

	if _, ok := store.Get(ctx, "ttl-key"); ok {
		t.Error("entry should be absent after TTL expiry")
	}
}

// TestRedisPendingStore_StoreError verifies that a Redis SET error is handled
// gracefully (logged, not panicked).
func TestRedisPendingStore_StoreError(t *testing.T) {
	store, mr := newTestRedisPendingStore(t)
	ctx := context.Background()

	mr.SetError("ERR forced")
	// Must not panic; the error is logged internally.
	store.Store(ctx, "err-key", pendingEscalation{
		JTI:       "jti-set-err",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	mr.SetError("") // clear error

	// Key must not have been stored.
	if _, ok := store.Get(ctx, "err-key"); ok {
		t.Error("entry should be absent when SET failed")
	}
}

// TestRedisPendingStore_GetError verifies that a Redis GET error (non-Nil) is
// handled gracefully and returns (zero, false).
func TestRedisPendingStore_GetError(t *testing.T) {
	store, mr := newTestRedisPendingStore(t)
	ctx := context.Background()

	// Store a valid entry first.
	store.Store(ctx, "gerr-key", pendingEscalation{
		JTI:       "jti-get-err",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	mr.SetError("ERR forced")
	_, ok := store.Get(ctx, "gerr-key")
	mr.SetError("")

	if ok {
		t.Error("Get should return false when Redis returns an error")
	}
}

// TestRedisPendingStore_DeleteError verifies that a Redis DEL error is handled
// gracefully (logged, not panicked).
func TestRedisPendingStore_DeleteError(t *testing.T) {
	store, mr := newTestRedisPendingStore(t)
	ctx := context.Background()

	store.Store(ctx, "del-err-key", pendingEscalation{
		JTI:       "jti-del-err",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	mr.SetError("ERR forced")
	// Must not panic.
	store.Delete(ctx, "del-err-key")
	mr.SetError("")
}
