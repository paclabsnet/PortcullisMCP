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
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRedisTokenStore(t *testing.T, scope string) (*RedisTokenStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })
	return NewRedisTokenStore(client, "test:", scope, nil), mr
}

// TestRedisTokenStore_AddAndAll verifies the basic add → all round-trip with
// session-scoped keys.
func TestRedisTokenStore_AddAndAll(t *testing.T) {
	store, _ := newTestRedisTokenStore(t, "session")
	ctx := withSessionID(context.Background(), "sess-add-all")

	raw := makeTestJWT(map[string]any{"jti": "tok-add-all", "exp": futureExp()})
	tok, err := store.Add(ctx, raw)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if tok.TokenID != "tok-add-all" {
		t.Errorf("TokenID = %q, want %q", tok.TokenID, "tok-add-all")
	}

	tokens := store.All(ctx)
	if len(tokens) != 1 || tokens[0].TokenID != "tok-add-all" {
		t.Errorf("All: expected [tok-add-all], got %v", tokens)
	}
}

// TestRedisTokenStore_Delete verifies that Delete removes token and set membership.
func TestRedisTokenStore_Delete(t *testing.T) {
	store, _ := newTestRedisTokenStore(t, "session")
	ctx := withSessionID(context.Background(), "sess-delete")

	raw := makeTestJWT(map[string]any{"jti": "tok-del", "exp": futureExp()})
	if _, err := store.Add(ctx, raw); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if err := store.Delete(ctx, "tok-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if tokens := store.All(ctx); len(tokens) != 0 {
		t.Errorf("expected empty after Delete, got %v", tokens)
	}
}

// TestRedisTokenStore_ScopedKeyFormat verifies that the token object key includes
// the user prefix, matching the design's scoped key pattern.
func TestRedisTokenStore_ScopedKeyFormat(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })

	store := NewRedisTokenStore(client, "ns:", "session", nil)
	ctx := withSessionID(context.Background(), "user1")

	raw := makeTestJWT(map[string]any{"jti": "jti-scope-fmt", "exp": futureExp()})
	if _, err := store.Add(ctx, raw); err != nil {
		t.Fatalf("Add: %v", err)
	}

	keys := mr.Keys()
	var tokKey, setKey string
	for _, k := range keys {
		if strings.Contains(k, "esc:tok:") {
			tokKey = k
		}
		if strings.Contains(k, "esc:set:") {
			setKey = k
		}
	}

	wantTokKey := "ns:esc:tok:sess:user1:jti-scope-fmt"
	if tokKey != wantTokKey {
		t.Errorf("token key = %q, want %q", tokKey, wantTokKey)
	}
	wantSetKey := "ns:esc:set:sess:user1"
	if setKey != wantSetKey {
		t.Errorf("set key = %q, want %q", setKey, wantSetKey)
	}
}

// TestRedisTokenStore_UnscopedKeyFormat verifies the unscoped (no prefix) key shape.
func TestRedisTokenStore_UnscopedKeyFormat(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })

	// scope="" → resolveStoragePrefix always returns "" → unscoped keys
	store := NewRedisTokenStore(client, "ns:", "", nil)
	ctx := context.Background()

	raw := makeTestJWT(map[string]any{"jti": "jti-unscoped", "exp": futureExp()})
	if _, err := store.Add(ctx, raw); err != nil {
		t.Fatalf("Add: %v", err)
	}

	keys := mr.Keys()
	var tokKey, setKey string
	for _, k := range keys {
		if strings.Contains(k, "esc:tok:") {
			tokKey = k
		}
		if strings.Contains(k, "esc:set:") {
			setKey = k
		}
	}

	if tokKey != "ns:esc:tok:jti-unscoped" {
		t.Errorf("unscoped token key = %q, want %q", tokKey, "ns:esc:tok:jti-unscoped")
	}
	if setKey != "ns:esc:set:default" {
		t.Errorf("unscoped set key = %q, want %q", setKey, "ns:esc:set:default")
	}
}

// TestRedisTokenStore_TTLFromJWT verifies the token key TTL is derived from the
// JWT exp claim rather than a hard-coded default.
func TestRedisTokenStore_TTLFromJWT(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })

	store := NewRedisTokenStore(client, "ns:", "session", nil)
	ctx := withSessionID(context.Background(), "sess-ttl")

	// exp = 5 seconds from now
	raw := makeTestJWT(map[string]any{
		"jti": "jti-ttl-jwt",
		"exp": float64(time.Now().Add(5 * time.Second).Unix()),
	})
	if _, err := store.Add(ctx, raw); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if tokens := store.All(ctx); len(tokens) != 1 {
		t.Fatalf("expected 1 token before expiry, got %d", len(tokens))
	}

	mr.FastForward(6 * time.Second)

	// After TTL, the token key is gone; All should return empty (stale set entry cleaned up).
	tokens := store.All(ctx)
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens after TTL expiry, got %d", len(tokens))
	}
}

// TestRedisTokenStore_CrossScopeIsolation verifies that two sessions cannot see
// each other's tokens.
func TestRedisTokenStore_CrossScopeIsolation(t *testing.T) {
	store, _ := newTestRedisTokenStore(t, "session")

	ctxA := withSessionID(context.Background(), "sess-a")
	ctxB := withSessionID(context.Background(), "sess-b")

	rawA := makeTestJWT(map[string]any{"jti": "tok-a", "exp": futureExp()})
	rawB := makeTestJWT(map[string]any{"jti": "tok-b", "exp": futureExp()})

	if _, err := store.Add(ctxA, rawA); err != nil {
		t.Fatalf("Add A: %v", err)
	}
	if _, err := store.Add(ctxB, rawB); err != nil {
		t.Fatalf("Add B: %v", err)
	}

	tokensA := store.All(ctxA)
	if len(tokensA) != 1 || tokensA[0].TokenID != "tok-a" {
		t.Errorf("session A sees wrong tokens: %v", tokensA)
	}

	tokensB := store.All(ctxB)
	if len(tokensB) != 1 || tokensB[0].TokenID != "tok-b" {
		t.Errorf("session B sees wrong tokens: %v", tokensB)
	}
}

// TestRedisTokenStore_FingerprintScope verifies Add/All/Delete under fingerprint scope.
func TestRedisTokenStore_FingerprintScope(t *testing.T) {
	store, _ := newTestRedisTokenStore(t, "fingerprint")
	ctx := withCredentialFingerprint(context.Background(), "fp-abc123")

	raw := makeTestJWT(map[string]any{"jti": "tok-fp", "exp": futureExp()})
	if _, err := store.Add(ctx, raw); err != nil {
		t.Fatalf("Add: %v", err)
	}

	tokens := store.All(ctx)
	if len(tokens) != 1 || tokens[0].TokenID != "tok-fp" {
		t.Errorf("expected [tok-fp], got %v", tokens)
	}

	// A different fingerprint sees nothing.
	ctxOther := withCredentialFingerprint(context.Background(), "fp-different")
	if other := store.All(ctxOther); len(other) != 0 {
		t.Errorf("different fingerprint should see 0 tokens, got %v", other)
	}

	if err := store.Delete(ctx, "tok-fp"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if tokens := store.All(ctx); len(tokens) != 0 {
		t.Errorf("expected empty after Delete, got %v", tokens)
	}
}

// TestRedisTokenStore_AllReturnsNilOnSMEMBERSError verifies that All gracefully
// handles a Redis error on SMEMBERS (returns nil, no panic).
func TestRedisTokenStore_AllReturnsNilOnSMEMBERSError(t *testing.T) {
	store, mr := newTestRedisTokenStore(t, "session")
	ctx := withSessionID(context.Background(), "sess-err")

	// Add a token so the set key exists, then force an error.
	raw := makeTestJWT(map[string]any{"jti": "tok-smembers-err", "exp": futureExp()})
	if _, err := store.Add(ctx, raw); err != nil {
		t.Fatalf("Add: %v", err)
	}

	mr.SetError("ERR forced")
	tokens := store.All(ctx)
	mr.SetError("")

	if tokens != nil {
		t.Errorf("All should return nil on SMEMBERS error, got %v", tokens)
	}
}

// TestRedisTokenStore_AddErrorIsPropagated verifies that a Redis pipeline error
// during Add is returned to the caller.
func TestRedisTokenStore_AddErrorIsPropagated(t *testing.T) {
	store, mr := newTestRedisTokenStore(t, "session")
	ctx := withSessionID(context.Background(), "sess-add-err")

	mr.SetError("ERR forced")
	raw := makeTestJWT(map[string]any{"jti": "tok-add-fail", "exp": futureExp()})
	_, err := store.Add(ctx, raw)
	mr.SetError("")

	if err == nil {
		t.Error("Add should propagate Redis pipeline error, got nil")
	}
}
