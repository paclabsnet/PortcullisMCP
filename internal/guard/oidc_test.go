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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// buildTestIDToken creates a minimal unsigned JWT-shaped ID token for tests.
// Signature is a placeholder — these tokens are only parsed unsafely.
func buildTestIDToken(sub, name, nonce string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := map[string]any{
		"sub":   sub,
		"name":  name,
		"nonce": nonce,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
	b, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(b)
	return header + "." + payload + ".fake-sig"
}

// newTestOIDCServer spins up a minimal OIDC server for use in integration tests.
// It handles discovery, the token endpoint, and refresh.
func newTestOIDCServer(t *testing.T, clientID, clientSecret string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			base := srv.URL
			_ = json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": base + "/authorize",
				"token_endpoint":         base + "/token",
			})
		case "/token":
			_ = r.ParseForm()
			grantType := r.FormValue("grant_type")
			nonce := ""
			if grantType == "authorization_code" {
				// Echo back the nonce from the stored PKCE state — tests must set it.
				nonce = r.FormValue("_test_nonce")
			}
			idToken := buildTestIDToken("user-123", "Alice Test", nonce)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "at-" + grantType,
				"refresh_token": "rt-" + grantType,
				"id_token":      idToken,
				"expires_in":    3600,
			})
		case "/token/invalid_grant":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newTestIdentityConfig builds a minimal IdentityConfig pointing at idpURL.
func newTestIdentityConfig(idpURL, redirectURI string) IdentityConfig {
	var cfg IdentityConfig
	cfg.Strategy = "oidc-login"
	cfg.Config.IssuerURL = idpURL
	cfg.Config.Client.ID = "test-client"
	cfg.Config.Client.Secret = "test-secret"
	cfg.Config.RedirectURI = redirectURI
	cfg.Config.Scopes = []string{"openid", "profile"}
	cfg.Config.Session.IdleTimeoutMins = 30
	cfg.Config.Session.MaxLifetimeHours = 24
	return cfg
}

func TestOIDCManagerStartLogin(t *testing.T) {
	idpSrv := newTestOIDCServer(t, "test-client", "test-secret")
	cfg := newTestIdentityConfig(idpSrv.URL, idpSrv.URL+"/callback")
	mgr := NewOIDCManager(cfg)

	authURL, ps, err := mgr.StartLogin(context.Background(), "/approve")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	q := u.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want code", q.Get("response_type"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("state") != ps.State {
		t.Errorf("state mismatch: URL %q vs PKCEState %q", q.Get("state"), ps.State)
	}
	if ps.ReturnPath != "/approve" {
		t.Errorf("return_path = %q, want /approve", ps.ReturnPath)
	}
	if ps.CodeVerifier == "" || ps.Nonce == "" {
		t.Error("expected non-empty code_verifier and nonce")
	}
}

func TestMemStoreSessionLifecycle(t *testing.T) {
	store := NewMemStore(100, 100, 100)
	ctx := context.Background()
	now := time.Now()

	sess := AuthSession{
		SessionID:    "sid-1",
		UserID:       "user-1",
		DisplayName:  "Alice",
		CreatedAt:    now,
		LastActiveAt: now,
	}

	t.Run("store_and_get", func(t *testing.T) {
		if err := store.StoreSession(ctx, sess); err != nil {
			t.Fatalf("StoreSession: %v", err)
		}
		got, err := store.GetSession(ctx, "sid-1")
		if err != nil {
			t.Fatalf("GetSession: %v", err)
		}
		if got == nil || got.UserID != "user-1" {
			t.Fatalf("unexpected session: %+v", got)
		}
	})

	t.Run("update_activity", func(t *testing.T) {
		before := sess.LastActiveAt
		time.Sleep(2 * time.Millisecond)
		if err := store.UpdateSessionActivity(ctx, "sid-1"); err != nil {
			t.Fatalf("UpdateSessionActivity: %v", err)
		}
		got, _ := store.GetSession(ctx, "sid-1")
		if !got.LastActiveAt.After(before) {
			t.Error("expected LastActiveAt to advance after UpdateSessionActivity")
		}
	})

	t.Run("delete", func(t *testing.T) {
		if err := store.DeleteSession(ctx, "sid-1"); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
		got, err := store.GetSession(ctx, "sid-1")
		if err != nil {
			t.Fatalf("GetSession after delete: %v", err)
		}
		if got != nil {
			t.Fatal("expected nil after delete")
		}
	})
}

func TestMemStorePKCELifecycle(t *testing.T) {
	store := NewMemStore(100, 100, 100)
	ctx := context.Background()

	ps := PKCEState{
		State:        "state-abc",
		Nonce:        "nonce-xyz",
		CodeVerifier: "verifier",
		ReturnPath:   "/approve",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}

	t.Run("store_and_get", func(t *testing.T) {
		if err := store.StorePKCE(ctx, ps); err != nil {
			t.Fatalf("StorePKCE: %v", err)
		}
		got, err := store.GetPKCE(ctx, "state-abc")
		if err != nil {
			t.Fatalf("GetPKCE: %v", err)
		}
		if got == nil || got.Nonce != "nonce-xyz" {
			t.Fatalf("unexpected PKCEState: %+v", got)
		}
	})

	t.Run("expired_returns_nil", func(t *testing.T) {
		expired := PKCEState{
			State:     "expired-state",
			ExpiresAt: time.Now().Add(-time.Second),
		}
		_ = store.StorePKCE(ctx, expired)
		got, err := store.GetPKCE(ctx, "expired-state")
		if err != nil {
			t.Fatalf("GetPKCE: %v", err)
		}
		if got != nil {
			t.Fatal("expected nil for expired PKCE state")
		}
	})

	t.Run("delete", func(t *testing.T) {
		_ = store.DeletePKCE(ctx, "state-abc")
		got, _ := store.GetPKCE(ctx, "state-abc")
		if got != nil {
			t.Fatal("expected nil after delete")
		}
	})
}

func TestAuthMiddlewareIdleTTL(t *testing.T) {
	store := NewMemStore(100, 100, 100)
	crypto := NewCookieCrypto("test-secret")

	// A session whose last-active time is well past the idle timeout.
	past := time.Now().Add(-2 * time.Hour)
	sess := AuthSession{
		SessionID:    "idle-sess",
		UserID:       "user-1",
		Tokens:       OIDCTokenSet{Expiry: time.Now().Add(time.Hour)},
		CreatedAt:    past,
		LastActiveAt: past,
	}
	_ = store.StoreSession(context.Background(), sess)

	// A minimal IdentityConfig with a 30-minute idle timeout.
	cfg := newTestIdentityConfig("http://idp.test", "http://guard.test/callback")

	mw := AuthMiddleware(store, nil, crypto, cfg)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	// Build a request that carries the encrypted session cookie.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/approve", nil)
	encID, _ := crypto.Encrypt("idle-sess")
	req.AddCookie(&http.Cookie{Name: cookieSession, Value: encID})

	handler.ServeHTTP(w, req)

	if called {
		t.Fatal("expected middleware to redirect, not call next handler")
	}
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/auth/login") {
		t.Fatalf("expected redirect to /auth/login, got %q", loc)
	}
}

func TestAuthMiddlewareMaxLifetime(t *testing.T) {
	store := NewMemStore(100, 100, 100)
	crypto := NewCookieCrypto("test-secret")

	// A session created more than 24 hours ago.
	longAgo := time.Now().Add(-25 * time.Hour)
	sess := AuthSession{
		SessionID:    "old-sess",
		UserID:       "user-1",
		Tokens:       OIDCTokenSet{Expiry: time.Now().Add(time.Hour)},
		CreatedAt:    longAgo,
		LastActiveAt: time.Now(),
	}
	_ = store.StoreSession(context.Background(), sess)

	cfg := newTestIdentityConfig("http://idp.test", "http://guard.test/callback")
	mw := AuthMiddleware(store, nil, crypto, cfg)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/approve", nil)
	encID, _ := crypto.Encrypt("old-sess")
	req.AddCookie(&http.Cookie{Name: cookieSession, Value: encID})

	handler.ServeHTTP(w, req)

	if called {
		t.Fatal("expected middleware to redirect, not call next handler")
	}
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
}

func TestAuthMiddlewareValidSession(t *testing.T) {
	store := NewMemStore(100, 100, 100)
	crypto := NewCookieCrypto("test-secret")

	sess := AuthSession{
		SessionID:    "valid-sess",
		UserID:       "user-1",
		DisplayName:  "Alice",
		Tokens:       OIDCTokenSet{Expiry: time.Now().Add(time.Hour)},
		CreatedAt:    time.Now(),
		LastActiveAt: time.Now(),
	}
	_ = store.StoreSession(context.Background(), sess)

	cfg := newTestIdentityConfig("http://idp.test", "http://guard.test/callback")
	mw := AuthMiddleware(store, nil, crypto, cfg)

	var gotSession *AuthSession
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSession = sessionFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/approve", nil)
	encID, _ := crypto.Encrypt("valid-sess")
	req.AddCookie(&http.Cookie{Name: cookieSession, Value: encID})

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotSession == nil || gotSession.UserID != "user-1" {
		t.Fatalf("expected session in context, got %+v", gotSession)
	}
}

func TestFullLoginFlow(t *testing.T) {
	// This test exercises the full login flow using a mock IdP:
	// handleAuthLogin -> PKCE state stored -> handleAuthCallback -> session created.

	store := NewMemStore(100, 100, 100)
	crypto := NewCookieCrypto("test-secret-32bytes-padding-here")

	// Build a mock IdP that serves discovery and a token endpoint.
	var callbackURL string
	var idpSrv *httptest.Server
	idpSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": idpSrv.URL + "/authorize",
				"token_endpoint":         idpSrv.URL + "/token",
			})
		case "/token":
			_ = r.ParseForm()
			nonce := r.FormValue("_test_nonce") // not a real param; tests inject it via URL
			idToken := buildTestIDToken("user-42", "Bob Test", nonce)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "access-tok",
				"refresh_token": "refresh-tok",
				"id_token":      idToken,
				"expires_in":    3600,
			})
		}
	}))
	defer idpSrv.Close()
	callbackURL = idpSrv.URL + "/callback"

	cfg := newTestIdentityConfig(idpSrv.URL, callbackURL)
	mgr := NewOIDCManager(cfg)

	// Step 1: Start login — get the PKCE state.
	authURL, pkceState, err := mgr.StartLogin(context.Background(), "/approve?jti=test123")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	_ = authURL

	// Persist PKCE state as the server would.
	if err := store.StorePKCE(context.Background(), pkceState); err != nil {
		t.Fatalf("StorePKCE: %v", err)
	}

	// Step 2: Simulate the IdP callback by calling HandleCallback directly.
	// We use the nonce from the PKCEState, and build a real ID token with it.
	idToken := buildTestIDToken("user-42", "Bob Test", pkceState.Nonce)
	// Inject the token exchange manually via a local mock token endpoint.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "at",
			"refresh_token": "rt",
			"id_token":      idToken,
			"expires_in":    3600,
		})
	}))
	defer tokenSrv.Close()

	// Point the manager at the token server by forcing discovery.
	mgr.discoverMu.Lock()
	mgr.authEndpoint = idpSrv.URL + "/authorize"
	mgr.tokenEndpoint = tokenSrv.URL
	mgr.discoverMu.Unlock()

	tokens, userID, displayName, err := mgr.HandleCallback(
		context.Background(), "auth-code", pkceState.CodeVerifier, pkceState.Nonce,
	)
	if err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}
	if userID != "user-42" {
		t.Errorf("userID = %q, want user-42", userID)
	}
	if displayName != "Bob Test" {
		t.Errorf("displayName = %q, want Bob Test", displayName)
	}
	if tokens.IDToken == "" {
		t.Error("expected non-empty IDToken")
	}

	// Step 3: Store session and verify round-trip.
	now := time.Now()
	sess := AuthSession{
		SessionID:    NewSessionID(),
		UserID:       userID,
		DisplayName:  displayName,
		Tokens:       *tokens,
		CreatedAt:    now,
		LastActiveAt: now,
	}
	if err := store.StoreSession(context.Background(), sess); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}

	got, err := store.GetSession(context.Background(), sess.SessionID)
	if err != nil || got == nil {
		t.Fatalf("GetSession: err=%v, session=%v", err, got)
	}
	if got.UserID != userID {
		t.Errorf("stored userID = %q, want %q", got.UserID, userID)
	}

	// Verify cookie encryption of the session ID.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/approve", nil)
	if err := SetSessionCookie(w, crypto, sess.SessionID, false); err != nil {
		t.Fatalf("SetSessionCookie: %v", err)
	}
	resp := w.Result()
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}
	gotID, err := GetSessionCookie(req, crypto)
	if err != nil {
		t.Fatalf("GetSessionCookie: %v", err)
	}
	if gotID != sess.SessionID {
		t.Errorf("cookie round-trip: got %q, want %q", gotID, sess.SessionID)
	}
}

func TestOpenRedirectPrevention(t *testing.T) {
	attacks := []struct {
		name  string
		input string
	}{
		{"absolute_http", "http://evil.com/steal"},
		{"absolute_https", "https://evil.com/steal"},
		{"protocol_relative", "//evil.com/steal"},
		{"unknown_path", "/settings"},
		{"deep_path", "/approve/../admin"},
	}
	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			got := validateReturnPath(tc.input)
			if got != "" {
				t.Errorf("validateReturnPath(%q) = %q; expected empty (blocked)", tc.input, got)
			}
		})
	}

	// Verify the safe case still works.
	safe := validateReturnPath("/approve?jti=abc")
	if safe == "" {
		t.Error("expected /approve?jti=abc to be allowed")
	}
}

func TestIsInvalidGrant(t *testing.T) {
	if !IsInvalidGrant(fmt.Errorf("invalid_grant: token revoked")) {
		t.Error("expected true for invalid_grant error")
	}
	if IsInvalidGrant(fmt.Errorf("server error")) {
		t.Error("expected false for non-invalid_grant error")
	}
	if IsInvalidGrant(nil) {
		t.Error("expected false for nil error")
	}
}
