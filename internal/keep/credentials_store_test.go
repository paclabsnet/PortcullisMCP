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
		if err := s.StorePending(ctx, "n1", p); err != nil {
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

	t.Run("client reg ops", func(t *testing.T) {
		reg := &clientReg{ClientID: "cid", ClientSecret: "sec"}
		if err := s.SetClientReg(ctx, "backend-a", reg); err != nil {
			t.Fatalf("SetClientReg: %v", err)
		}
		got, err := s.GetClientReg(ctx, "backend-a")
		if err != nil {
			t.Fatalf("GetClientReg error: %v", err)
		}
		if got == nil || got.ClientID != "cid" {
			t.Errorf("GetClientReg: want ClientID=cid, got %v", got)
		}
		// Miss
		miss, err := s.GetClientReg(ctx, "unknown-backend")
		if err != nil || miss != nil {
			t.Errorf("GetClientReg miss: want nil, got %v", miss)
		}
	})
}
