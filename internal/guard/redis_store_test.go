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

package guard

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newTestRedisClient starts an in-process miniredis server and returns a
// connected client.  The server is shut down when the test ends.
func newTestRedisClient(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

// ---- RedisPendingStore ------------------------------------------------------

func TestRedisPendingStore_StoreAndGet(t *testing.T) {
	ctx := context.Background()
	s := NewRedisPendingStore(newTestRedisClient(t), "")

	req := PendingRequest{
		JTI:       "test-jti-1",
		JWT:       "header.payload.sig",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.StorePending(ctx, req); err != nil {
		t.Fatalf("StorePending: %v", err)
	}

	got, ok, err := s.GetPending(ctx, req.JTI)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if !ok {
		t.Fatal("expected found=true, got false")
	}
	if got.JTI != req.JTI || got.JWT != req.JWT {
		t.Errorf("got %+v, want %+v", got, req)
	}
}

func TestRedisPendingStore_GetMissing(t *testing.T) {
	ctx := context.Background()
	s := NewRedisPendingStore(newTestRedisClient(t), "")

	_, ok, err := s.GetPending(ctx, "no-such-jti")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected found=false for missing key")
	}
}

func TestRedisPendingStore_TTLExpiry(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	s := NewRedisPendingStore(redis.NewClient(&redis.Options{Addr: mr.Addr()}), "")

	req := PendingRequest{
		JTI:       "expiring-jti",
		JWT:       "h.p.s",
		ExpiresAt: time.Now().Add(2 * time.Second),
	}
	if err := s.StorePending(ctx, req); err != nil {
		t.Fatalf("StorePending: %v", err)
	}

	// Fast-forward time in miniredis past the TTL.
	mr.FastForward(3 * time.Second)

	_, ok, err := s.GetPending(ctx, req.JTI)
	if err != nil {
		t.Fatalf("GetPending after expiry: %v", err)
	}
	if ok {
		t.Error("expected found=false after TTL expiry")
	}
}

func TestRedisPendingStore_StoreAlreadyExpired(t *testing.T) {
	ctx := context.Background()
	s := NewRedisPendingStore(newTestRedisClient(t), "")

	// Storing an already-expired entry should be a no-op (not an error).
	req := PendingRequest{
		JTI:       "already-expired",
		JWT:       "h.p.s",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := s.StorePending(ctx, req); err != nil {
		t.Fatalf("StorePending already expired: %v", err)
	}
	_, ok, err := s.GetPending(ctx, req.JTI)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if ok {
		t.Error("expected not found for already-expired entry")
	}
}

func TestRedisPendingStore_PurgeExpiredIsNoOp(t *testing.T) {
	ctx := context.Background()
	s := NewRedisPendingStore(newTestRedisClient(t), "")
	// Should succeed without error (Redis TTL handles cleanup).
	if err := s.PurgeExpired(ctx); err != nil {
		t.Errorf("PurgeExpired: %v", err)
	}
}

// ---- RedisUnclaimedStore ----------------------------------------------------

func TestRedisUnclaimedStore_AddAndList(t *testing.T) {
	ctx := context.Background()
	s := NewRedisUnclaimedStore(newTestRedisClient(t), "", 0)

	tok := UnclaimedToken{
		UserID:    "alice@corp.com",
		JTI:       "tok-jti-1",
		Raw:       "escalation.jwt.value",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.AddUnclaimed(ctx, tok); err != nil {
		t.Fatalf("AddUnclaimed: %v", err)
	}

	list, err := s.ListUnclaimed(ctx, tok.UserID)
	if err != nil {
		t.Fatalf("ListUnclaimed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 token, got %d", len(list))
	}
	if list[0].JTI != tok.JTI || list[0].Raw != tok.Raw {
		t.Errorf("listed token = %+v, want %+v", list[0], tok)
	}
}

func TestRedisUnclaimedStore_ListEmptyUser(t *testing.T) {
	ctx := context.Background()
	s := NewRedisUnclaimedStore(newTestRedisClient(t), "", 0)

	list, err := s.ListUnclaimed(ctx, "nobody@corp.com")
	if err != nil {
		t.Fatalf("ListUnclaimed for unknown user: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d entries", len(list))
	}
}

func TestRedisUnclaimedStore_ClaimToken_Success(t *testing.T) {
	ctx := context.Background()
	s := NewRedisUnclaimedStore(newTestRedisClient(t), "", 0)

	tok := UnclaimedToken{
		UserID:    "bob@corp.com",
		JTI:       "claim-me",
		Raw:       "escalation-token-raw",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.AddUnclaimed(ctx, tok); err != nil {
		t.Fatalf("AddUnclaimed: %v", err)
	}

	// First claim — should succeed.
	claimed, err := s.ClaimToken(ctx, tok.JTI)
	if err != nil {
		t.Fatalf("ClaimToken: %v", err)
	}
	if claimed == nil {
		t.Fatal("expected non-nil claimed token")
	}
	if claimed.Raw != tok.Raw {
		t.Errorf("claimed.Raw = %q, want %q", claimed.Raw, tok.Raw)
	}

	// Second claim — must return nil (already consumed).
	claimed2, err := s.ClaimToken(ctx, tok.JTI)
	if err != nil {
		t.Fatalf("second ClaimToken error: %v", err)
	}
	if claimed2 != nil {
		t.Error("second claim should return nil (token already consumed)")
	}
}

func TestRedisUnclaimedStore_ClaimToken_NotFound(t *testing.T) {
	ctx := context.Background()
	s := NewRedisUnclaimedStore(newTestRedisClient(t), "", 0)

	claimed, err := s.ClaimToken(ctx, "nonexistent-jti")
	if err != nil {
		t.Fatalf("ClaimToken nonexistent: %v", err)
	}
	if claimed != nil {
		t.Error("expected nil for non-existent JTI")
	}
}

func TestRedisUnclaimedStore_CapacityExceeded(t *testing.T) {
	ctx := context.Background()
	// maxPerUser = 2
	s := NewRedisUnclaimedStore(newTestRedisClient(t), "", 2)

	add := func(jti string) error {
		return s.AddUnclaimed(ctx, UnclaimedToken{
			UserID:    "cap-user@corp.com",
			JTI:       jti,
			Raw:       "raw",
			ExpiresAt: time.Now().Add(time.Hour),
		})
	}

	if err := add("jti-1"); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := add("jti-2"); err != nil {
		t.Fatalf("second add: %v", err)
	}
	if err := add("jti-3"); !errors.Is(err, ErrCapacityExceeded) {
		t.Errorf("third add: want ErrCapacityExceeded, got %v", err)
	}
}

func TestRedisUnclaimedStore_TTLExpiry_HidesFromList(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	s := NewRedisUnclaimedStore(redis.NewClient(&redis.Options{Addr: mr.Addr()}), "", 0)

	tok := UnclaimedToken{
		UserID:    "expiry-user@corp.com",
		JTI:       "expiring-tok",
		Raw:       "raw",
		ExpiresAt: time.Now().Add(2 * time.Second),
	}
	if err := s.AddUnclaimed(ctx, tok); err != nil {
		t.Fatalf("AddUnclaimed: %v", err)
	}

	// Fast-forward past the TTL.
	mr.FastForward(3 * time.Second)

	list, err := s.ListUnclaimed(ctx, tok.UserID)
	if err != nil {
		t.Fatalf("ListUnclaimed after expiry: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list after TTL expiry, got %d entries", len(list))
	}
}

func TestRedisUnclaimedStore_PurgeExpiredIsNoOp(t *testing.T) {
	ctx := context.Background()
	s := NewRedisUnclaimedStore(newTestRedisClient(t), "", 0)
	if err := s.PurgeExpired(ctx); err != nil {
		t.Errorf("PurgeExpired: %v", err)
	}
}

func TestRedisUnclaimedStore_MultipleUsers(t *testing.T) {
	ctx := context.Background()
	s := NewRedisUnclaimedStore(newTestRedisClient(t), "", 0)

	for _, tc := range []struct{ user, jti string }{
		{"alice@corp.com", "jti-a"},
		{"bob@corp.com", "jti-b"},
	} {
		if err := s.AddUnclaimed(ctx, UnclaimedToken{
			UserID:    tc.user,
			JTI:       tc.jti,
			Raw:       "raw-" + tc.jti,
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("AddUnclaimed %s: %v", tc.user, err)
		}
	}

	aliceTokens, _ := s.ListUnclaimed(ctx, "alice@corp.com")
	bobTokens, _ := s.ListUnclaimed(ctx, "bob@corp.com")
	if len(aliceTokens) != 1 || aliceTokens[0].JTI != "jti-a" {
		t.Errorf("alice: %+v", aliceTokens)
	}
	if len(bobTokens) != 1 || bobTokens[0].JTI != "jti-b" {
		t.Errorf("bob: %+v", bobTokens)
	}
}

// ---- NewRedisClient ---------------------------------------------------------

func TestNewRedisClient_ConnectsToMiniredis(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	client, err := NewRedisClient(ctx, RedisConfig{Addr: mr.Addr()})
	if err != nil {
		t.Fatalf("NewRedisClient: %v", err)
	}
	_ = client.Close()
}

func TestNewRedisClient_FailsOnBadAddr(t *testing.T) {
	ctx := context.Background()
	_, err := NewRedisClient(ctx, RedisConfig{Addr: "127.0.0.1:1"})
	if err == nil {
		t.Fatal("expected error for unreachable address")
	}
}
