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
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// makeTestJWT builds a structurally valid JWT with the given claims.
// The signature is a dummy; TokenStore does not verify signatures.
func makeTestJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + ".fakesignature"
}

// futureExp and expiredExp return JWT "exp" timestamps as float64.
// Go's encoding/json decodes all JSON numbers into map[string]any as float64,
// so the claim map must use float64 here to match what real JWT parsing produces.
func futureExp() float64 {
	return float64(time.Now().Add(time.Hour).Unix())
}

func expiredExp() float64 {
	return float64(time.Now().Add(-time.Hour).Unix())
}

func TestParseEscalationToken_Valid(t *testing.T) {
	raw := makeTestJWT(map[string]any{
		"jti":        "tok-001",
		"sub":        "user@example.com",
		"exp":        futureExp(),
		"granted_by": "manager@example.com",
	})

	tok, err := parseEscalationToken(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.TokenID != "tok-001" {
		t.Errorf("TokenID = %q, want %q", tok.TokenID, "tok-001")
	}
	if tok.GrantedBy != "manager@example.com" {
		t.Errorf("GrantedBy = %q, want %q", tok.GrantedBy, "manager@example.com")
	}
	if tok.Raw != raw {
		t.Error("Raw should be preserved as-is")
	}
}

func TestParseEscalationToken_FallsBackToSub(t *testing.T) {
	// No jti claim — should fall back to sub.
	raw := makeTestJWT(map[string]any{
		"sub": "user@example.com",
		"exp": futureExp(),
	})
	tok, err := parseEscalationToken(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.TokenID != "user@example.com" {
		t.Errorf("TokenID = %q, want %q", tok.TokenID, "user@example.com")
	}
}

func TestParseEscalationToken_Expired(t *testing.T) {
	raw := makeTestJWT(map[string]any{
		"jti": "old-tok",
		"exp": expiredExp(),
	})
	_, err := parseEscalationToken(raw)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestParseEscalationToken_MissingIDClaims(t *testing.T) {
	// Neither jti nor sub present — must be rejected.
	raw := makeTestJWT(map[string]any{
		"exp": futureExp(),
	})
	_, err := parseEscalationToken(raw)
	if err == nil {
		t.Fatal("expected error for token missing jti/sub, got nil")
	}
}

func TestParseEscalationToken_NotAJWT(t *testing.T) {
	_, err := parseEscalationToken("not.a.valid.jwt.at.all")
	if err == nil {
		t.Fatal("expected error for malformed token, got nil")
	}
}

func TestParseEscalationToken_NoExpClaim(t *testing.T) {
	// Tokens without an exp claim are accepted (no expiry check).
	raw := makeTestJWT(map[string]any{
		"jti": "no-exp",
	})
	tok, err := parseEscalationToken(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.TokenID != "no-exp" {
		t.Errorf("TokenID = %q, want %q", tok.TokenID, "no-exp")
	}
}

func TestTokenStore_AddAndAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	ts, err := NewTokenStore(context.Background(), path)
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}

	raw := makeTestJWT(map[string]any{"jti": "t1", "exp": futureExp()})
	tok, err := ts.Add(context.Background(), raw)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if tok.TokenID != "t1" {
		t.Errorf("returned TokenID = %q, want %q", tok.TokenID, "t1")
	}

	all := ts.All()
	if len(all) != 1 {
		t.Fatalf("All() returned %d tokens, want 1", len(all))
	}
	if all[0].TokenID != "t1" {
		t.Errorf("All()[0].TokenID = %q, want %q", all[0].TokenID, "t1")
	}
}

func TestTokenStore_Persistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")

	// Add a token via first store instance.
	ts1, _ := NewTokenStore(context.Background(), path)
	raw := makeTestJWT(map[string]any{"jti": "persist-me", "exp": futureExp()})
	if _, err := ts1.Add(context.Background(), raw); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Load a second store from the same file.
	ts2, err := NewTokenStore(context.Background(), path)
	if err != nil {
		t.Fatalf("second NewTokenStore: %v", err)
	}
	all := ts2.All()
	if len(all) != 1 {
		t.Fatalf("second store has %d tokens, want 1", len(all))
	}
	if all[0].TokenID != "persist-me" {
		t.Errorf("persisted TokenID = %q, want %q", all[0].TokenID, "persist-me")
	}
}

func TestTokenStore_Delete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	ts, _ := NewTokenStore(context.Background(), path)

	raw := makeTestJWT(map[string]any{"jti": "del-me", "exp": futureExp()})
	ts.Add(context.Background(), raw)

	if err := ts.Delete(context.Background(), "del-me"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(ts.All()) != 0 {
		t.Error("expected empty store after delete")
	}
}

func TestTokenStore_Delete_NotFound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	ts, _ := NewTokenStore(context.Background(), path)

	if err := ts.Delete(context.Background(), "nonexistent"); err == nil {
		t.Error("expected error deleting nonexistent token, got nil")
	}
}

func TestTokenStore_DuplicateReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	ts, _ := NewTokenStore(context.Background(), path)

	raw1 := makeTestJWT(map[string]any{"jti": "dup", "exp": futureExp(), "granted_by": "first"})
	raw2 := makeTestJWT(map[string]any{"jti": "dup", "exp": futureExp(), "granted_by": "second"})

	ts.Add(context.Background(), raw1)
	ts.Add(context.Background(), raw2)

	all := ts.All()
	if len(all) != 1 {
		t.Fatalf("expected 1 token after duplicate replacement, got %d", len(all))
	}
	if all[0].GrantedBy != "second" {
		t.Errorf("GrantedBy = %q, want %q (replacement)", all[0].GrantedBy, "second")
	}
}

func TestTokenStore_NonExistentFile(t *testing.T) {
	// File does not exist — store should start empty without error.
	path := filepath.Join(t.TempDir(), "does-not-exist", "tokens.json")
	ts, err := NewTokenStore(context.Background(), path)
	if err != nil {
		t.Fatalf("NewTokenStore on missing file: %v", err)
	}
	if len(ts.All()) != 0 {
		t.Error("expected empty store for non-existent file")
	}
}

func TestTokenStore_PrunesExpiredOnLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")

	// Write a mix of valid and expired tokens directly to the file.
	validRaw := makeTestJWT(map[string]any{"jti": "valid", "exp": futureExp()})
	expiredRaw := makeTestJWT(map[string]any{"jti": "expired", "exp": expiredExp()})
	data, _ := json.Marshal([]string{validRaw, expiredRaw})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	ts, err := NewTokenStore(context.Background(), path)
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	all := ts.All()
	if len(all) != 1 {
		t.Fatalf("expected 1 token (expired pruned), got %d", len(all))
	}
	if all[0].TokenID != "valid" {
		t.Errorf("TokenID = %q, want %q", all[0].TokenID, "valid")
	}
}

func TestTokenStore_FilePermissions(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; permission check not meaningful")
	}
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission bits not enforced on Windows")
	}
	path := filepath.Join(t.TempDir(), "tokens.json")
	ts, _ := NewTokenStore(context.Background(), path)
	raw := makeTestJWT(map[string]any{"jti": "perm-test", "exp": futureExp()})
	ts.Add(context.Background(), raw)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("token file mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestExpandHome(t *testing.T) {
	t.Run("no tilde", func(t *testing.T) {
		got, err := expandHome("/etc/hosts")
		if err != nil {
			t.Fatal(err)
		}
		if got != "/etc/hosts" {
			t.Errorf("expandHome(%q) = %q, want %q", "/etc/hosts", got, "/etc/hosts")
		}
	})

	t.Run("tilde prefix", func(t *testing.T) {
		got, err := expandHome("~/foo/bar")
		if err != nil {
			t.Fatal(err)
		}
		home, _ := os.UserHomeDir()
		want := filepath.Join(home, "foo/bar")
		if got != want {
			t.Errorf("expandHome(~/foo/bar) = %q, want %q", got, want)
		}
	})
}
