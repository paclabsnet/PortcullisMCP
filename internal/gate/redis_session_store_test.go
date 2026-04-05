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
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newTestRedisStore starts a miniredis server and returns the store + a cleanup func.
func newTestRedisStore(t *testing.T, ttlSeconds int) (*RedisSessionStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedisSessionStoreFromClient(client, ttlSeconds)
	return store, mr
}

func TestRedisSessionStore(t *testing.T) {
	ctx := context.Background()

	t.Run("save and get round-trips correctly", func(t *testing.T) {
		store, _ := newTestRedisStore(t, 3600)
		state := []byte(`{"fingerprint":"redis-test"}`)
		if err := store.SaveSession(ctx, "sess-1", "user-a", state); err != nil {
			t.Fatalf("SaveSession: %v", err)
		}
		gotState, gotUser, err := store.GetSession(ctx, "sess-1")
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if gotUser != "user-a" {
			t.Errorf("userID = %q, want %q", gotUser, "user-a")
		}
		if !bytes.Equal(gotState, state) {
			t.Errorf("state = %q, want %q", gotState, state)
		}
	})

	t.Run("missing session returns ErrSessionNotFound", func(t *testing.T) {
		store, _ := newTestRedisStore(t, 3600)
		_, _, err := store.GetSession(ctx, "no-such-session")
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("expected ErrSessionNotFound, got: %v", err)
		}
	})

	t.Run("delete removes session", func(t *testing.T) {
		store, _ := newTestRedisStore(t, 3600)
		_ = store.SaveSession(ctx, "sess-del", "user-b", []byte("state"))
		if err := store.DeleteSession(ctx, "sess-del"); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
		_, _, err := store.GetSession(ctx, "sess-del")
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("expected ErrSessionNotFound after delete, got: %v", err)
		}
	})

	t.Run("TTL is applied — expired session returns ErrSessionNotFound", func(t *testing.T) {
		store, mr := newTestRedisStore(t, 1) // 1-second TTL
		if err := store.SaveSession(ctx, "sess-ttl", "user-ttl", []byte("data")); err != nil {
			t.Fatalf("SaveSession: %v", err)
		}
		// Verify the key exists immediately.
		_, _, err := store.GetSession(ctx, "sess-ttl")
		if err != nil {
			t.Fatalf("GetSession before expiry: %v", err)
		}
		// Advance miniredis clock past the TTL.
		mr.FastForward(2 * time.Second)
		_, _, err = store.GetSession(ctx, "sess-ttl")
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("expected ErrSessionNotFound after TTL expiry, got: %v", err)
		}
	})

	t.Run("overwrite refreshes state and TTL", func(t *testing.T) {
		store, mr := newTestRedisStore(t, 5)
		_ = store.SaveSession(ctx, "sess-ow", "user-old", []byte("old"))
		mr.FastForward(3 * time.Second) // consume 3 of 5 seconds
		// Overwrite — should reset TTL to 5 seconds from now.
		_ = store.SaveSession(ctx, "sess-ow", "user-new", []byte("new"))
		mr.FastForward(4 * time.Second) // 4 more seconds; would have expired at original TTL
		gotState, gotUser, err := store.GetSession(ctx, "sess-ow")
		if err != nil {
			t.Fatalf("GetSession after overwrite: %v", err)
		}
		if gotUser != "user-new" {
			t.Errorf("userID = %q, want %q", gotUser, "user-new")
		}
		if string(gotState) != "new" {
			t.Errorf("state = %q, want %q", gotState, "new")
		}
	})

	t.Run("nil state is stored and retrieved", func(t *testing.T) {
		store, _ := newTestRedisStore(t, 3600)
		if err := store.SaveSession(ctx, "sess-nil", "user-nil", nil); err != nil {
			t.Fatalf("SaveSession nil state: %v", err)
		}
		gotState, gotUser, err := store.GetSession(ctx, "sess-nil")
		if err != nil {
			t.Fatalf("GetSession nil state: %v", err)
		}
		if gotUser != "user-nil" {
			t.Errorf("userID = %q, want %q", gotUser, "user-nil")
		}
		if len(gotState) != 0 {
			t.Errorf("expected empty state, got: %q", gotState)
		}
	})
}
