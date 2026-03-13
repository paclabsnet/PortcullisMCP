package gate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// buildJWT creates a structurally valid but signature-less JWT for testing
// identity parsing (which explicitly skips signature verification).
func buildJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + ".dummy"
}

// TestUnsafeParseJWTClaims covers the low-level claim extractor.
func TestUnsafeParseJWTClaims(t *testing.T) {
	t.Run("valid JWT returns claims", func(t *testing.T) {
		raw := buildJWT(map[string]any{"sub": "alice", "iss": "test"})
		claims, err := unsafeParseJWTClaims(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims["sub"] != "alice" {
			t.Errorf("sub = %v, want alice", claims["sub"])
		}
	})

	t.Run("not a JWT — too few parts", func(t *testing.T) {
		_, err := unsafeParseJWTClaims("one.two")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("invalid base64 payload", func(t *testing.T) {
		_, err := unsafeParseJWTClaims("header.!!invalid!!.sig")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("payload is not JSON", func(t *testing.T) {
		notJSON := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
		_, err := unsafeParseJWTClaims("h." + notJSON + ".s")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestIdentityFromJWT_SubClaim(t *testing.T) {
	raw := buildJWT(map[string]any{
		"sub":  "user@corp.com",
		"name": "Corp User",
		"exp":  float64(time.Now().Add(time.Hour).Unix()),
	})
	id, expiry, err := identityFromJWT(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.UserID != "user@corp.com" {
		t.Errorf("UserID = %q, want %q", id.UserID, "user@corp.com")
	}
	if id.DisplayName != "Corp User" {
		t.Errorf("DisplayName = %q, want %q", id.DisplayName, "Corp User")
	}
	if id.SourceType != "oidc" {
		t.Errorf("SourceType = %q, want oidc", id.SourceType)
	}
	if expiry.IsZero() {
		t.Error("expected non-zero expiry")
	}
}

func TestIdentityFromJWT_FallbackToUPN(t *testing.T) {
	// No sub claim; should fall back to upn.
	raw := buildJWT(map[string]any{
		"upn": "upn@corp.com",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	id, _, err := identityFromJWT(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.UserID != "upn@corp.com" {
		t.Errorf("UserID = %q, want upn@corp.com", id.UserID)
	}
}

func TestIdentityFromJWT_FallbackToEmail(t *testing.T) {
	// No sub or upn; should fall back to email.
	raw := buildJWT(map[string]any{
		"email": "email@corp.com",
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
	})
	id, _, err := identityFromJWT(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.UserID != "email@corp.com" {
		t.Errorf("UserID = %q, want email@corp.com", id.UserID)
	}
}

func TestIdentityFromJWT_PreferredUsername(t *testing.T) {
	// preferred_username used as DisplayName when name claim absent.
	raw := buildJWT(map[string]any{
		"sub":                "u@corp.com",
		"preferred_username": "u.username",
		"exp":                float64(time.Now().Add(time.Hour).Unix()),
	})
	id, _, err := identityFromJWT(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.DisplayName != "u.username" {
		t.Errorf("DisplayName = %q, want u.username", id.DisplayName)
	}
}

func TestIdentityFromJWT_Groups(t *testing.T) {
	raw := buildJWT(map[string]any{
		"sub":    "u@corp.com",
		"groups": []any{"admins", "devs"},
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
	})
	id, _, err := identityFromJWT(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(id.Groups) != 2 {
		t.Fatalf("Groups = %v, want 2 entries", id.Groups)
	}
	if id.Groups[0] != "admins" || id.Groups[1] != "devs" {
		t.Errorf("Groups = %v, want [admins devs]", id.Groups)
	}
}

func TestIdentityFromJWT_MissingSubject(t *testing.T) {
	// No sub, upn, or email — should return error.
	raw := buildJWT(map[string]any{
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	_, _, err := identityFromJWT(raw)
	if err == nil {
		t.Fatal("expected error for missing subject claim, got nil")
	}
}

func TestIdentityFromJWT_NoExpClaim(t *testing.T) {
	// Tokens without exp are allowed; expiry returns zero time.
	raw := buildJWT(map[string]any{"sub": "u@corp.com"})
	id, expiry, err := identityFromJWT(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.UserID != "u@corp.com" {
		t.Errorf("UserID = %q, want u@corp.com", id.UserID)
	}
	if !expiry.IsZero() {
		t.Errorf("expected zero expiry without exp claim, got %v", expiry)
	}
}

func TestIdentityFromJWT_RawTokenPreserved(t *testing.T) {
	raw := buildJWT(map[string]any{"sub": "u@corp.com"})
	id, _, _ := identityFromJWT(raw)
	if id.RawToken != raw {
		t.Error("RawToken should be the original JWT string")
	}
}

func TestResolveOSIdentity_Override(t *testing.T) {
	cfg := IdentityConfig{
		Source:      "os",
		UserID:      "override-user@test",
		DisplayName: "Override Display",
		Groups:      []string{"testers"},
	}
	id, err := resolveOSIdentity(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.UserID != "override-user@test" {
		t.Errorf("UserID = %q, want override-user@test", id.UserID)
	}
	if id.DisplayName != "Override Display" {
		t.Errorf("DisplayName = %q, want Override Display", id.DisplayName)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "testers" {
		t.Errorf("Groups = %v, want [testers]", id.Groups)
	}
	if id.SourceType != "os" {
		t.Errorf("SourceType = %q, want os", id.SourceType)
	}
}

func TestResolveOSIdentity_SystemUser(t *testing.T) {
	// Empty override — should use actual OS user without error.
	cfg := IdentityConfig{Source: "os"}
	id, err := resolveOSIdentity(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.UserID == "" {
		t.Error("expected non-empty UserID from OS identity")
	}
	if id.SourceType != "os" {
		t.Errorf("SourceType = %q, want os", id.SourceType)
	}
}

func TestIdentityCache_OSSource(t *testing.T) {
	cfg := IdentityConfig{Source: "os", UserID: "cache-test@example.com"}
	cache, err := NewIdentityCache(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewIdentityCache: %v", err)
	}
	id := cache.Get(context.Background())
	if id.UserID != "cache-test@example.com" {
		t.Errorf("UserID = %q, want cache-test@example.com", id.UserID)
	}
}

func TestIdentityCache_Info(t *testing.T) {
	cfg := IdentityConfig{Source: "os", UserID: "info-test@example.com", DisplayName: "Info Test"}
	cache, err := NewIdentityCache(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewIdentityCache: %v", err)
	}
	info := cache.Info()
	if info.UserID != "info-test@example.com" {
		t.Errorf("Info.UserID = %q, want info-test@example.com", info.UserID)
	}
	if info.SourceType != "os" {
		t.Errorf("Info.SourceType = %q, want os", info.SourceType)
	}
	if info.TokenExpiry != nil {
		t.Error("expected nil TokenExpiry for OS identity")
	}
}

func TestIdentityCache_OIDCSource(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "oidc-token")

	raw := buildJWT(map[string]any{
		"sub": "oidc-user@corp.com",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	if err := os.WriteFile(tokenFile, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := IdentityConfig{
		Source: "oidc",
		OIDC:   OIDCConfig{TokenFile: tokenFile},
	}
	cache, err := NewIdentityCache(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewIdentityCache: %v", err)
	}
	id := cache.Get(context.Background())
	if id.UserID != "oidc-user@corp.com" {
		t.Errorf("UserID = %q, want oidc-user@corp.com", id.UserID)
	}
	if id.SourceType != "oidc" {
		t.Errorf("SourceType = %q, want oidc", id.SourceType)
	}

	// Info should report a non-nil TokenExpiry.
	info := cache.Info()
	if info.TokenExpiry == nil {
		t.Error("expected non-nil TokenExpiry for OIDC identity with exp claim")
	}
}

func TestIdentityCache_OIDCFallsBackToOS(t *testing.T) {
	// OIDC source with a missing token file — should fall back to OS identity.
	cfg := IdentityConfig{
		Source: "oidc",
		OIDC:   OIDCConfig{TokenFile: "/does/not/exist/token"},
		UserID: "fallback@example.com",
	}
	cache, err := NewIdentityCache(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewIdentityCache should fall back to OS, got error: %v", err)
	}
	id := cache.Get(context.Background())
	// Fell back to OS; UserID should be the override.
	if id.UserID != "fallback@example.com" {
		t.Errorf("UserID = %q, want fallback@example.com", id.UserID)
	}
	if id.SourceType != "os" {
		t.Errorf("SourceType = %q, want os after fallback", id.SourceType)
	}
}

func TestIdentityCache_UpdateToken(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "oidc-token")

	initial := buildJWT(map[string]any{
		"sub": "old@corp.com",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	os.WriteFile(tokenFile, []byte(initial), 0600)

	cfg := IdentityConfig{
		Source: "oidc",
		OIDC:   OIDCConfig{TokenFile: tokenFile},
	}
	cache, _ := NewIdentityCache(context.Background(), cfg)

	newRaw := buildJWT(map[string]any{
		"sub": "new@corp.com",
		"exp": float64(time.Now().Add(2 * time.Hour).Unix()),
	})
	id, err := cache.UpdateToken(newRaw)
	if err != nil {
		t.Fatalf("UpdateToken: %v", err)
	}
	if id.UserID != "new@corp.com" {
		t.Errorf("updated UserID = %q, want new@corp.com", id.UserID)
	}

	// Cache should now return the updated identity.
	cached := cache.Get(context.Background())
	if cached.UserID != "new@corp.com" {
		t.Errorf("cached UserID after update = %q, want new@corp.com", cached.UserID)
	}

	// File should have been written.
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	if string(data) != newRaw+"\n" {
		t.Errorf("token file content = %q, want %q", string(data), newRaw+"\n")
	}
}

func TestIdentityCache_UpdateToken_NotOIDCSource(t *testing.T) {
	cfg := IdentityConfig{Source: "os", UserID: "u@example.com"}
	cache, _ := NewIdentityCache(context.Background(), cfg)

	_, err := cache.UpdateToken("any-token")
	if err == nil {
		t.Fatal("expected error when updating token on non-OIDC source, got nil")
	}
}
