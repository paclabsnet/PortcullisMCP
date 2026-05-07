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
)

func newTestRedisCredStore(t *testing.T) CredentialsStore {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewUniversalClient(&redis.UniversalOptions{Addrs: []string{mr.Addr()}})
	t.Cleanup(func() { _ = client.Close() })
	return NewRedisCredentialsStore(client, "test:")
}

func TestRedisCredentialsStore_Tokens(t *testing.T) {
	ctx := context.Background()
	s := newTestRedisCredStore(t)

	token := &userToken{
		AccessToken: "tok-abc",
		Expiry:      time.Now().Add(time.Hour),
	}

	if err := s.SetToken(ctx, "backend1", "user1", token); err != nil {
		t.Fatalf("SetToken: %v", err)
	}

	got, err := s.GetToken(ctx, "backend1", "user1")
	if err != nil || got == nil || got.AccessToken != "tok-abc" {
		t.Errorf("GetToken: got %v, err=%v", got, err)
	}

	// Miss for different user
	miss, err := s.GetToken(ctx, "backend1", "other-user")
	if err != nil || miss != nil {
		t.Errorf("GetToken miss: want nil, got %v err=%v", miss, err)
	}

	if err := s.DeleteToken(ctx, "backend1", "user1"); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
	after, err := s.GetToken(ctx, "backend1", "user1")
	if err != nil || after != nil {
		t.Errorf("GetToken after delete: want nil, got %v", after)
	}
}

func TestRedisCredentialsStore_Pending(t *testing.T) {
	ctx := context.Background()
	s := newTestRedisCredStore(t)

	p := &pendingAuth{
		CodeVerifier:  "verifier-xyz",
		BackendName:   "be",
		UserID:        "u1",
		TokenEndpoint: "https://auth.example/token",
	}

	if err := s.StorePending(ctx, "nonce-1", p); err != nil {
		t.Fatalf("StorePending: %v", err)
	}

	// First consume returns data and deletes.
	got, err := s.ConsumePending(ctx, "nonce-1")
	if err != nil || got == nil || got.CodeVerifier != "verifier-xyz" {
		t.Errorf("ConsumePending first: got %v, err=%v", got, err)
	}

	// Second consume returns nil (already deleted by GETDEL).
	got2, err := s.ConsumePending(ctx, "nonce-1")
	if err != nil || got2 != nil {
		t.Errorf("ConsumePending second: expected nil, got %v err=%v", got2, err)
	}

	// Unknown nonce.
	got3, err := s.ConsumePending(ctx, "never-stored")
	if err != nil || got3 != nil {
		t.Errorf("ConsumePending unknown: expected nil, got %v err=%v", got3, err)
	}
}

func TestRedisCredentialsStore_ClientReg(t *testing.T) {
	ctx := context.Background()
	s := newTestRedisCredStore(t)

	reg := &clientReg{ClientID: "cid", ClientSecret: "sec"}
	if err := s.SetClientReg(ctx, "my-backend", reg); err != nil {
		t.Fatalf("SetClientReg: %v", err)
	}

	got, err := s.GetClientReg(ctx, "my-backend")
	if err != nil || got == nil || got.ClientID != "cid" {
		t.Errorf("GetClientReg: got %v, err=%v", got, err)
	}

	miss, err := s.GetClientReg(ctx, "unknown")
	if err != nil || miss != nil {
		t.Errorf("GetClientReg miss: want nil, got %v err=%v", miss, err)
	}
}
