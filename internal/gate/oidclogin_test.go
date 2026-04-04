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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestOIDCServer starts a minimal fake OIDC provider backed by httptest.
// It returns the server and a function to close it.
// discoveryBody overrides the discovery document; pass nil to use a valid default.
// tokenHandler overrides the /token endpoint; pass nil to use a default that
// returns a valid token response.
func newTestOIDCServer(t *testing.T, discoveryBody map[string]any, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if discoveryBody != nil {
			_ = json.NewEncoder(w).Encode(discoveryBody)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         srv.URL + "/token",
		})
	})

	if tokenHandler != nil {
		mux.HandleFunc("/token", tokenHandler)
	} else {
		mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "test-access-token",
				"refresh_token": "test-refresh-token",
				"id_token":      buildJWT(map[string]any{"sub": "sub123", "nonce": "test-nonce", "exp": time.Now().Add(1 * time.Hour).Unix()}),
				"expires_in":    3600,
			})
		})
	}

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestLoginManager(t *testing.T, issuerURL string) (*OIDCLoginManager, *StateMachine) {
	t.Helper()
	sm := NewStateMachine()
	cfg := OIDCLoginConfig{
		IssuerURL: issuerURL,
		ClientID:  "test-client",
		Scopes:    []string{"openid"},
	}
	m := NewOIDCLoginManager(cfg, DefaultManagementAPIPort, 0, sm, nil, nil, nil, nil)
	return m, sm
}

// TestDiscover_Success verifies that discovery populates the endpoints and
// that a second call does not make another HTTP request (cache hit).
func TestDiscover_Success(t *testing.T) {
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": "https://idp.example.com/auth",
			"token_endpoint":         "https://idp.example.com/token",
		})
	}))
	t.Cleanup(srv.Close)

	m, _ := newTestLoginManager(t, srv.URL)

	if err := m.discover(context.Background()); err != nil {
		t.Fatalf("first discover: %v", err)
	}
	if m.authEndpoint == "" || m.tokenEndpoint == "" {
		t.Fatal("endpoints not populated after successful discovery")
	}

	// Second call must not hit the server again.
	if err := m.discover(context.Background()); err != nil {
		t.Fatalf("second discover: %v", err)
	}
	if requestCount != 1 {
		t.Errorf("expected 1 HTTP request, got %d", requestCount)
	}
}

// TestDiscover_FailureThenSuccess verifies that a failed discovery attempt is
// not cached and the next call retries successfully.
func TestDiscover_FailureThenSuccess(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": "https://idp.example.com/auth",
			"token_endpoint":         "https://idp.example.com/token",
		})
	}))
	t.Cleanup(srv.Close)

	m, _ := newTestLoginManager(t, srv.URL)

	// First attempt should fail.
	if err := m.discover(context.Background()); err == nil {
		t.Fatal("expected error on first discovery attempt, got nil")
	}
	if m.authEndpoint != "" || m.tokenEndpoint != "" {
		t.Fatal("endpoints must not be cached after a failed discovery")
	}

	// Second attempt should succeed.
	if err := m.discover(context.Background()); err != nil {
		t.Fatalf("second discover: %v", err)
	}
	if m.authEndpoint == "" || m.tokenEndpoint == "" {
		t.Fatal("endpoints not populated after retry")
	}
	if callCount != 2 {
		t.Errorf("expected 2 HTTP requests, got %d", callCount)
	}
}

// TestDiscover_MissingEndpoints verifies that a discovery document missing
// required fields returns an error and is not cached.
func TestDiscover_MissingEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Missing token_endpoint
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": "https://idp.example.com/auth",
		})
	}))
	t.Cleanup(srv.Close)

	m, _ := newTestLoginManager(t, srv.URL)

	err := m.discover(context.Background())
	if err == nil {
		t.Fatal("expected error for missing token_endpoint")
	}
	if !strings.Contains(err.Error(), "token_endpoint") {
		t.Errorf("error should mention token_endpoint, got: %v", err)
	}
	// Endpoints must not be partially cached.
	if m.authEndpoint != "" || m.tokenEndpoint != "" {
		t.Fatal("endpoints must not be cached after partial discovery document")
	}
}

// TestStartLogin_BuildsAuthURL verifies that StartLogin returns a well-formed
// authorization URL and transitions the state machine to authenticating.
func TestStartLogin_BuildsAuthURL(t *testing.T) {
	srv := newTestOIDCServer(t, nil, nil)
	m, sm := newTestLoginManager(t, srv.URL)

	authURL, err := m.StartLogin(context.Background())
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}

	for _, param := range []string{"response_type=code", "code_challenge_method=S256", "code_challenge=", "state=", "nonce=", "client_id=test-client"} {
		if !strings.Contains(authURL, param) {
			t.Errorf("auth URL missing %q: %s", param, authURL)
		}
	}

	if sm.State() != StateAuthenticating {
		t.Errorf("expected StateAuthenticating, got %v", sm.StateLabel())
	}
}

// TestStartLogin_StoresSession verifies that StartLogin stores a PKCE session
// keyed by the state parameter.
func TestStartLogin_StoresSession(t *testing.T) {
	srv := newTestOIDCServer(t, nil, nil)
	m, _ := newTestLoginManager(t, srv.URL)

	authURL, err := m.StartLogin(context.Background())
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}

	// Extract state from URL
	idx := strings.Index(authURL, "state=")
	if idx < 0 {
		t.Fatal("no state param in auth URL")
	}
	stateAndRest := authURL[idx+6:]
	state := stateAndRest
	if amp := strings.IndexByte(stateAndRest, '&'); amp >= 0 {
		state = stateAndRest[:amp]
	}

	m.mu.Lock()
	session, ok := m.sessions[state]
	m.mu.Unlock()

	if !ok {
		t.Fatal("no session stored for state param")
	}
	if session.codeVerifier == "" || session.codeChallenge == "" || session.nonce == "" {
		t.Error("session missing required PKCE fields")
	}
	if session.expiresAt.Before(time.Now()) {
		t.Error("session already expired at creation")
	}
}

// TestHandleCallback_Success verifies the full callback flow: correct state,
// code exchange, nonce validation, authenticated state, and callback invocation.
func TestHandleCallback_Success(t *testing.T) {
	var authedToken string
	srv := newTestOIDCServer(t, nil, nil) // default token handler returns valid tokens
	sm := NewStateMachine()
	cfg := OIDCLoginConfig{
		IssuerURL: srv.URL,
		ClientID:  "test-client",
		Scopes:    []string{"openid"},
	}
	m := NewOIDCLoginManager(cfg, DefaultManagementAPIPort, 0, sm,
		nil, // no IdentitySource in this test
		func(raw string) { authedToken = raw },
		nil, nil,
	)

	authURL, err := m.StartLogin(context.Background())
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}

	// Extract state
	idx := strings.Index(authURL, "state=")
	stateAndRest := authURL[idx+6:]
	state := stateAndRest
	if amp := strings.IndexByte(stateAndRest, '&'); amp >= 0 {
		state = stateAndRest[:amp]
	}

	// Extract the nonce that StartLogin stored so we can build a matching id_token.
	m.mu.Lock()
	nonce := m.sessions[state].nonce
	m.mu.Unlock()

	// Start a token server that returns an id_token with the correct nonce.
	// We cannot reuse srv because its /token handler was built before we knew
	// the nonce; instead we override m.tokenEndpoint directly.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "test-access",
			"refresh_token": "test-refresh",
			"id_token":      buildJWT(map[string]any{"sub": "user1", "nonce": nonce, "exp": time.Now().Add(1 * time.Hour).Unix()}),
			"expires_in":    3600,
		})
	}))
	t.Cleanup(tokenSrv.Close)

	m.discoverMu.Lock()
	m.tokenEndpoint = tokenSrv.URL + "/token"
	m.discoverMu.Unlock()

	if err := m.HandleCallback(context.Background(), state, "auth-code-xyz", "", ""); err != nil {
		t.Fatalf("HandleCallback: %v", err)
	}

	if sm.State() != StateAuthenticated {
		t.Errorf("expected StateAuthenticated, got %v", sm.StateLabel())
	}
	if authedToken == "" {
		t.Error("onAuthenticated callback was not invoked")
	}
}

// TestHandleCallback_UnknownState verifies that an unknown state param causes
// an error and transitions to system-error:invalid.
func TestHandleCallback_UnknownState(t *testing.T) {
	srv := newTestOIDCServer(t, nil, nil)
	m, sm := newTestLoginManager(t, srv.URL)

	err := m.HandleCallback(context.Background(), "unknown-state", "some-code", "", "")
	if err == nil {
		t.Fatal("expected error for unknown state")
	}
	if sm.State() != StateSystemError || sm.Substate() != SubstateInvalid {
		t.Errorf("expected system-error:invalid, got %v", sm.StateLabel())
	}
}

// TestHandleCallback_IdPError verifies that an IdP error param causes
// system-error:invalid.
func TestHandleCallback_IdPError(t *testing.T) {
	srv := newTestOIDCServer(t, nil, nil)
	m, sm := newTestLoginManager(t, srv.URL)

	err := m.HandleCallback(context.Background(), "", "", "access_denied", "user denied consent")
	if err == nil {
		t.Fatal("expected error for IdP error")
	}
	if sm.State() != StateSystemError || sm.Substate() != SubstateInvalid {
		t.Errorf("expected system-error:invalid, got %v", sm.StateLabel())
	}
	if !strings.Contains(err.Error(), "access_denied") {
		t.Errorf("error should mention IdP error code, got: %v", err)
	}
}

// TestHandleCallback_ExpiredSession verifies that a session past its expiry
// is rejected.
func TestHandleCallback_ExpiredSession(t *testing.T) {
	srv := newTestOIDCServer(t, nil, nil)
	m, _ := newTestLoginManager(t, srv.URL)

	// Inject an already-expired session directly.
	m.mu.Lock()
	m.sessions["expired-state"] = &pkceSession{
		state:     "expired-state",
		expiresAt: time.Now().Add(-1 * time.Minute),
	}
	m.mu.Unlock()

	err := m.HandleCallback(context.Background(), "expired-state", "code", "", "")
	if err == nil {
		t.Fatal("expected error for expired session")
	}
}

// TestStartLogin_CallbackTimeout_ConfiguredExpiry verifies that the PKCE session
// expiry reflects login_callback_timeout_seconds when non-zero.
func TestStartLogin_CallbackTimeout_ConfiguredExpiry(t *testing.T) {
	srv := newTestOIDCServer(t, nil, nil)
	sm := NewStateMachine()
	cfg := OIDCLoginConfig{IssuerURL: srv.URL, ClientID: "test-client"}
	timeoutSecs := 120
	m := NewOIDCLoginManager(cfg, DefaultManagementAPIPort, timeoutSecs, sm, nil, nil, nil, nil)

	authURL, err := m.StartLogin(context.Background())
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}

	idx := strings.Index(authURL, "state=")
	stateAndRest := authURL[idx+6:]
	state := stateAndRest
	if amp := strings.IndexByte(stateAndRest, '&'); amp >= 0 {
		state = stateAndRest[:amp]
	}

	m.mu.Lock()
	session := m.sessions[state]
	m.mu.Unlock()

	want := time.Duration(timeoutSecs) * time.Second
	got := time.Until(session.expiresAt)
	// Allow a small delta for test execution time.
	if got < want-2*time.Second || got > want+2*time.Second {
		t.Errorf("session expiry = %v, want ~%v (login_callback_timeout_seconds=%d)", got.Round(time.Second), want, timeoutSecs)
	}
}

// TestStartLogin_CallbackTimeout_DefaultExpiry verifies that timeout=0 uses the
// 10-minute default.
func TestStartLogin_CallbackTimeout_DefaultExpiry(t *testing.T) {
	srv := newTestOIDCServer(t, nil, nil)
	m, _ := newTestLoginManager(t, srv.URL) // passes 0 → default

	authURL, err := m.StartLogin(context.Background())
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}

	idx := strings.Index(authURL, "state=")
	stateAndRest := authURL[idx+6:]
	state := stateAndRest
	if amp := strings.IndexByte(stateAndRest, '&'); amp >= 0 {
		state = stateAndRest[:amp]
	}

	m.mu.Lock()
	session := m.sessions[state]
	m.mu.Unlock()

	got := time.Until(session.expiresAt)
	if got < 9*time.Minute || got > 11*time.Minute {
		t.Errorf("default session expiry = %v, want ~10m", got.Round(time.Second))
	}
}

// TestIsInvalidGrant verifies the grant expiry detection used to distinguish
// natural refresh token expiry from network/server errors.
func TestIsInvalidGrant(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{fmt.Errorf("invalid_grant"), true},
		{fmt.Errorf("invalid_grant: token expired"), true},
		{fmt.Errorf("network error"), false},
		{fmt.Errorf("invalid_request"), false},
	}
	for _, tc := range tests {
		if got := isInvalidGrant(tc.err); got != tc.want {
			t.Errorf("isInvalidGrant(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// TestPKCEChallenge verifies the S256 code challenge is computed correctly.
func TestPKCEChallenge(t *testing.T) {
	// Known vector: verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// should produce challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	// (RFC 7636 appendix B)
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := pkceChallenge(verifier); got != want {
		t.Errorf("pkceChallenge = %q, want %q", got, want)
	}
}

// TestRedirectURI verifies redirect URI construction from mgmtPort.
func TestRedirectURI(t *testing.T) {
	tests := []struct {
		mgmtPort    int
		cfgRedirect string
		want        string
	}{
		{0, "", fmt.Sprintf("http://localhost:%d/auth/callback", DefaultManagementAPIPort)},
		{8888, "", "http://localhost:8888/auth/callback"},
		{0, "http://custom.example.com/callback", "http://custom.example.com/callback"},
	}
	for _, tc := range tests {
		m := &OIDCLoginManager{
			cfg:      OIDCLoginConfig{RedirectURI: tc.cfgRedirect},
			mgmtPort: tc.mgmtPort,
		}
		if got := m.redirectURI(); got != tc.want {
			t.Errorf("redirectURI(port=%d, cfg=%q) = %q, want %q", tc.mgmtPort, tc.cfgRedirect, got, tc.want)
		}
	}
}
