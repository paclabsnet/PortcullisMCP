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
)

func TestMemoryCredentialsStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryCredentialsStore()

	t.Run("token ops", func(t *testing.T) {
		token := &userToken{AccessToken: "abc", Expiry: time.Now().Add(time.Hour)}
		if err := s.SetToken(ctx, "b1", "u1", token); err != nil {
			t.Fatalf("SetToken: %v", err)
		}
		got, err := s.GetToken(ctx, "b1", "u1")
		if err != nil {
			t.Fatalf("GetToken error: %v", err)
		}
		if got == nil || got.AccessToken != "abc" {
			t.Errorf("GetToken: want AccessToken=abc, got %v", got)
		}

		// Miss for different user
		miss, err := s.GetToken(ctx, "b1", "u2")
		if err != nil || miss != nil {
			t.Errorf("GetToken miss: want nil, got %v err=%v", miss, err)
		}

		// Delete
		if err := s.DeleteToken(ctx, "b1", "u1"); err != nil {
			t.Fatalf("DeleteToken: %v", err)
		}
		after, err := s.GetToken(ctx, "b1", "u1")
		if err != nil || after != nil {
			t.Errorf("GetToken after delete: want nil, got %v", after)
		}
	})

	t.Run("pending ops (consume deletes)", func(t *testing.T) {
		p := &pendingAuth{CodeVerifier: "v1", BackendName: "be", UserID: "u1"}
		if err := s.StorePending(ctx, "n1", p, time.Minute); err != nil {
			t.Fatalf("StorePending: %v", err)
		}
		gotP, err := s.ConsumePending(ctx, "n1")
		if err != nil {
			t.Fatalf("ConsumePending error: %v", err)
		}
		if gotP == nil || gotP.CodeVerifier != "v1" {
			t.Errorf("ConsumePending: want CodeVerifier=v1, got %v", gotP)
		}
		// Second consume must return nil (consumed)
		gotP2, err := s.ConsumePending(ctx, "n1")
		if err != nil || gotP2 != nil {
			t.Errorf("Expected nil after consume, got %v err=%v", gotP2, err)
		}
	})

	t.Run("pending miss", func(t *testing.T) {
		got, err := s.ConsumePending(ctx, "nonexistent-nonce")
		if err != nil || got != nil {
			t.Errorf("Expected (nil,nil) for unknown nonce, got %v err=%v", got, err)
		}
	})

	t.Run("pending entry expired by TTL", func(t *testing.T) {
		fresh := NewMemoryCredentialsStore()
		p := &pendingAuth{CodeVerifier: "exp-verifier"}
		// Store with a tiny TTL; sleep until it has definitely passed.
		if err := fresh.StorePending(ctx, "exp-nonce", p, time.Millisecond); err != nil {
			t.Fatalf("StorePending: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
		got, err := fresh.ConsumePending(ctx, "exp-nonce")
		if err != nil || got != nil {
			t.Errorf("Expected (nil,nil) for expired nonce, got %v err=%v", got, err)
		}
	})

	t.Run("client reg ops (SetClientRegNX)", func(t *testing.T) {
		reg := &clientReg{
			ClientID:                "cid",
			ClientSecret:            "sec",
			TokenEndpointAuthMethod: "client_secret_basic",
			Scopes:                  "openid profile",
		}
		// First set should succeed (NX = not exists)
		set, err := s.SetClientRegNX(ctx, "backend-a", reg)
		if err != nil {
			t.Fatalf("SetClientRegNX: %v", err)
		}
		if !set {
			t.Error("SetClientRegNX: expected true on first set")
		}

		got, err := s.GetClientReg(ctx, "backend-a")
		if err != nil {
			t.Fatalf("GetClientReg error: %v", err)
		}
		if got == nil || got.ClientID != "cid" {
			t.Errorf("GetClientReg: want ClientID=cid, got %v", got)
		}
		if got.TokenEndpointAuthMethod != "client_secret_basic" {
			t.Errorf("GetClientReg: want TokenEndpointAuthMethod=client_secret_basic, got %q", got.TokenEndpointAuthMethod)
		}
		if got.Scopes != "openid profile" {
			t.Errorf("GetClientReg: want Scopes='openid profile', got %q", got.Scopes)
		}

		// Second set should be a no-op
		set2, err := s.SetClientRegNX(ctx, "backend-a", &clientReg{ClientID: "other"})
		if err != nil {
			t.Fatalf("SetClientRegNX (second): %v", err)
		}
		if set2 {
			t.Error("SetClientRegNX: expected false on second set (already exists)")
		}
		// Original should still be there
		got2, _ := s.GetClientReg(ctx, "backend-a")
		if got2 == nil || got2.ClientID != "cid" {
			t.Errorf("GetClientReg after no-op SetNX: want cid, got %v", got2)
		}

		// Miss
		miss, err := s.GetClientReg(ctx, "unknown-backend")
		if err != nil || miss != nil {
			t.Errorf("GetClientReg miss: want nil, got %v", miss)
		}
	})

	t.Run("LockDCR", func(t *testing.T) {
		unlock, err := s.LockDCR(ctx, "backend-lock")
		if err != nil {
			t.Fatalf("LockDCR: %v", err)
		}
		// Unlock should not panic
		unlock()
		// Re-locking after unlock should work
		unlock2, err := s.LockDCR(ctx, "backend-lock")
		if err != nil {
			t.Fatalf("LockDCR (second): %v", err)
		}
		unlock2()
	})

	t.Run("DCR failure cache", func(t *testing.T) {
		// No failure initially
		reason, err := s.GetDCRFailure(ctx, "backend-dcr-fail")
		if err != nil || reason != "" {
			t.Errorf("GetDCRFailure: want empty, got %q err=%v", reason, err)
		}

		// Set a failure
		if err := s.SetDCRFailure(ctx, "backend-dcr-fail", "invalid_software_statement", 10*time.Minute); err != nil {
			t.Fatalf("SetDCRFailure: %v", err)
		}

		// Should be visible
		reason, err = s.GetDCRFailure(ctx, "backend-dcr-fail")
		if err != nil {
			t.Fatalf("GetDCRFailure error: %v", err)
		}
		if reason != "invalid_software_statement" {
			t.Errorf("GetDCRFailure: want 'invalid_software_statement', got %q", reason)
		}
	})

	t.Run("DCR failure cache expiry", func(t *testing.T) {
		fresh := NewMemoryCredentialsStore()
		if err := fresh.SetDCRFailure(ctx, "b", "err", time.Millisecond); err != nil {
			t.Fatalf("SetDCRFailure: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
		reason, err := fresh.GetDCRFailure(ctx, "b")
		if err != nil || reason != "" {
			t.Errorf("GetDCRFailure after expiry: want empty, got %q err=%v", reason, err)
		}
	})
}
