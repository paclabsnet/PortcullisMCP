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
	"slices"
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

// newTestRedisStoreWithPrefix starts a miniredis server and returns a store that
// uses the given key prefix, sharing the same miniredis instance when mr is non-nil.
func newTestRedisStoreWithPrefix(t *testing.T, mr *miniredis.Miniredis, prefix string) *RedisSessionStore {
	t.Helper()
	if mr == nil {
		mr = miniredis.RunT(t)
	}
	return NewRedisSessionStore(RedisConfig{
		Addr:      mr.Addr(),
		KeyPrefix: prefix,
	}, 3600)
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

// collectAfter drains the After iterator into a [][]byte for easy comparison.
func collectAfter(t *testing.T, store *RedisSessionStore, sessionID, streamID string, index int) [][]byte {
	t.Helper()
	var out [][]byte
	for data, err := range store.After(context.Background(), sessionID, streamID, index) {
		if err != nil {
			t.Fatalf("After iterator error: %v", err)
		}
		out = append(out, data)
	}
	return out
}

func TestRedisEventStore(t *testing.T) {
	ctx := context.Background()

	t.Run("Open is a no-op and Append creates the list", func(t *testing.T) {
		store, _ := newTestRedisStore(t, 3600)
		if err := store.Open(ctx, "s1", "stream-a"); err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := store.Append(ctx, "s1", "stream-a", []byte("hello")); err != nil {
			t.Fatalf("Append: %v", err)
		}
		got := collectAfter(t, store, "s1", "stream-a", -1)
		if len(got) != 1 || !bytes.Equal(got[0], []byte("hello")) {
			t.Errorf("After(-1) = %v, want [hello]", got)
		}
	})

	t.Run("After(-1) returns all appended events", func(t *testing.T) {
		store, _ := newTestRedisStore(t, 3600)
		events := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
		for _, e := range events {
			if err := store.Append(ctx, "s2", "stream-b", e); err != nil {
				t.Fatalf("Append: %v", err)
			}
		}
		got := collectAfter(t, store, "s2", "stream-b", -1)
		if !slices.EqualFunc(got, events, bytes.Equal) {
			t.Errorf("After(-1) = %v, want %v", got, events)
		}
	})

	t.Run("After(n) returns only events after index n", func(t *testing.T) {
		store, _ := newTestRedisStore(t, 3600)
		for _, e := range []string{"x", "y", "z"} {
			_ = store.Append(ctx, "s3", "stream-c", []byte(e))
		}
		// After(0) means "after the first item" — should return ["y","z"]
		got := collectAfter(t, store, "s3", "stream-c", 0)
		want := [][]byte{[]byte("y"), []byte("z")}
		if !slices.EqualFunc(got, want, bytes.Equal) {
			t.Errorf("After(0) = %v, want %v", got, want)
		}
		// After(1) should return only ["z"]
		got = collectAfter(t, store, "s3", "stream-c", 1)
		want = [][]byte{[]byte("z")}
		if !slices.EqualFunc(got, want, bytes.Equal) {
			t.Errorf("After(1) = %v, want %v", got, want)
		}
	})

	t.Run("After on empty stream returns empty slice without error", func(t *testing.T) {
		store, _ := newTestRedisStore(t, 3600)
		got := collectAfter(t, store, "s4", "no-such-stream", -1)
		if len(got) != 0 {
			t.Errorf("expected empty result, got %v", got)
		}
	})

	t.Run("SessionClosed removes all event keys for the session", func(t *testing.T) {
		store, _ := newTestRedisStore(t, 3600)
		_ = store.Append(ctx, "s5", "stream-1", []byte("data1"))
		_ = store.Append(ctx, "s5", "stream-2", []byte("data2"))
		// Both streams visible before close.
		if got := collectAfter(t, store, "s5", "stream-1", -1); len(got) == 0 {
			t.Fatal("expected data in stream-1 before SessionClosed")
		}
		if err := store.SessionClosed(ctx, "s5"); err != nil {
			t.Fatalf("SessionClosed: %v", err)
		}
		// Both streams should now be empty (keys deleted).
		if got := collectAfter(t, store, "s5", "stream-1", -1); len(got) != 0 {
			t.Errorf("stream-1 not cleared after SessionClosed: %v", got)
		}
		if got := collectAfter(t, store, "s5", "stream-2", -1); len(got) != 0 {
			t.Errorf("stream-2 not cleared after SessionClosed: %v", got)
		}
	})

	t.Run("SessionClosed on unknown session is a no-op", func(t *testing.T) {
		store, _ := newTestRedisStore(t, 3600)
		if err := store.SessionClosed(ctx, "no-such-session"); err != nil {
			t.Errorf("SessionClosed on unknown session: %v", err)
		}
	})

	t.Run("Append refreshes TTL — events survive past original TTL", func(t *testing.T) {
		store, mr := newTestRedisStore(t, 5)
		_ = store.Append(ctx, "s6", "stream-ttl", []byte("first"))
		mr.FastForward(3 * time.Second) // 3 of 5 seconds elapsed
		_ = store.Append(ctx, "s6", "stream-ttl", []byte("second"))
		// TTL refreshed to 5s from now; advancing 4 more seconds should still be valid.
		mr.FastForward(4 * time.Second)
		got := collectAfter(t, store, "s6", "stream-ttl", -1)
		if len(got) != 2 {
			t.Errorf("expected 2 events after TTL refresh, got %d: %v", len(got), got)
		}
	})

	t.Run("events expire after TTL without further appends", func(t *testing.T) {
		store, mr := newTestRedisStore(t, 1) // 1-second TTL
		_ = store.Append(ctx, "s7", "stream-exp", []byte("gone"))
		mr.FastForward(2 * time.Second)
		got := collectAfter(t, store, "s7", "stream-exp", -1)
		if len(got) != 0 {
			t.Errorf("expected empty result after expiry, got %v", got)
		}
	})
}

func TestRedisSessionStore_KeyPrefix(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)

	t.Run("default prefix is applied when KeyPrefix is empty", func(t *testing.T) {
		store := newTestRedisStoreWithPrefix(t, mr, "")
		if store.keyPrefix != defaultRedisKeyPrefix {
			t.Errorf("keyPrefix = %q, want %q", store.keyPrefix, defaultRedisKeyPrefix)
		}
	})

	t.Run("custom prefix is used for session keys", func(t *testing.T) {
		store := newTestRedisStoreWithPrefix(t, mr, "env-a:")
		_ = store.SaveSession(ctx, "sess-prefix", "user", []byte("state"))
		// The raw Redis key must include the custom prefix.
		expectedKey := "env-a:session:sess-prefix"
		if !mr.Exists(expectedKey) {
			t.Errorf("expected Redis key %q not found; key prefix not applied", expectedKey)
		}
	})

	t.Run("two stores with different prefixes are isolated", func(t *testing.T) {
		storeA := newTestRedisStoreWithPrefix(t, mr, "prod:")
		storeB := newTestRedisStoreWithPrefix(t, mr, "staging:")

		_ = storeA.SaveSession(ctx, "shared-id", "prod-user", []byte("prod-state"))

		// storeB uses a different prefix so "shared-id" does not exist there.
		_, _, err := storeB.GetSession(ctx, "shared-id")
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("expected ErrSessionNotFound in staging namespace, got: %v", err)
		}

		// storeA can still read its own session.
		gotState, gotUser, err := storeA.GetSession(ctx, "shared-id")
		if err != nil {
			t.Fatalf("storeA.GetSession: %v", err)
		}
		if gotUser != "prod-user" || string(gotState) != "prod-state" {
			t.Errorf("storeA round-trip failed: user=%q state=%q", gotUser, gotState)
		}
	})

	t.Run("custom prefix is used for event keys", func(t *testing.T) {
		store := newTestRedisStoreWithPrefix(t, mr, "env-b:")
		_ = store.Append(ctx, "sess-ev", "stream-1", []byte("data"))
		expectedKey := "env-b:events:sess-ev:stream-1"
		if !mr.Exists(expectedKey) {
			t.Errorf("expected Redis event key %q not found; key prefix not applied", expectedKey)
		}
	})
}
