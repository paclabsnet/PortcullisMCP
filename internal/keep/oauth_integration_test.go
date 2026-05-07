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

//go:build integration

package keep

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestOAuthIntegration exercises the full OAuth 2.1 PKCE authorization-code flow:
//
//  1. Router.tryStartOAuthFlow is called; it stores pending state and returns an auth URL.
//  2. Test simulates the user's browser following the redirect to the callback endpoint.
//  3. Server.handleOAuthCallback exchanges the code for a token and stores it.
//  4. The token can be retrieved from CredentialsStore and injected on subsequent calls.
func TestOAuthIntegration(t *testing.T) {
	ctx := context.Background()

	const (
		backendName = "integration-backend"
		clientID    = "test-client"
		testUserID  = "user-int-001"
		accessToken = "at-integration-xyz"
		authCode    = "code-from-provider"
	)

	var capturedVerifier string

	// Mock token endpoint: validates the request and issues a token.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		capturedVerifier = r.FormValue("code_verifier")
		if r.FormValue("code") != authCode {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	credStore := NewMemoryCredentialsStore()

	// Build a Server with the credStore; the callback handler uses it.
	srv := &Server{
		cfg: Config{
			Responsibility: ResponsibilityConfig{
				Backends: []BackendConfig{
					{
						Name: backendName,
						UserIdentity: BackendUserIdentity{
							Type: "oauth",
							OAuth: BackendOAuth{
								ClientID:           clientID,
								StoreRefreshTokens: false,
							},
						},
					},
				},
			},
		},
		credStore: credStore,
	}

	// Serve the callback via a test HTTP server.
	callbackServer := httptest.NewServer(http.HandlerFunc(srv.handleOAuthCallback))
	defer callbackServer.Close()

	callbackURL := callbackServer.URL + "/oauth/callback"

	// Build a Router with the same credStore and an oauth backend.
	router := &Router{
		backends:  make(map[string]*backendConn),
		credStore: credStore,
	}
	router.backends[backendName] = &backendConn{
		cfg: BackendConfig{
			Name: backendName,
			UserIdentity: BackendUserIdentity{
				Type: "oauth",
				OAuth: BackendOAuth{
					ClientID:              clientID,
					AuthorizationEndpoint: "https://auth.example/authorize",
					TokenEndpoint:         tokenServer.URL + "/token",
					CallbackURL:           callbackURL,
					Scopes:                []string{"openid"},
					StoreRefreshTokens:    false,
				},
			},
		},
	}

	// Also update the Server's backend config to know the real token endpoint.
	srv.cfg.Responsibility.Backends[0].UserIdentity.OAuth.TokenEndpoint = tokenServer.URL + "/token"
	srv.cfg.Responsibility.Backends[0].UserIdentity.OAuth.CallbackURL = callbackURL

	// Step 1: Initiate the OAuth flow.
	authResult, err := router.tryStartOAuthFlow(ctx, backendName, testUserID)
	if err != nil {
		t.Fatalf("tryStartOAuthFlow: %v", err)
	}
	if !authResult.IsError {
		t.Fatal("expected IsError=true (auth URL response), got false")
	}

	// Extract the auth URL from the result text.
	text := authResult.Content[0].(*mcp.TextContent).Text
	authURLStr := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "https://auth.example/authorize") {
			authURLStr = line
			break
		}
	}
	if authURLStr == "" {
		t.Fatalf("could not find auth URL in: %q", text)
	}

	parsed, err := url.Parse(authURLStr)
	if err != nil {
		t.Fatalf("parse auth URL: %v", err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("no state in auth URL")
	}
	if parsed.Query().Get("code_challenge_method") != "S256" {
		t.Error("expected code_challenge_method=S256")
	}

	// Step 2 & 3: Simulate the browser redirect to the callback URL.
	simCallback := callbackURL + "?code=" + authCode + "&state=" + state
	resp, err := http.Get(simCallback) //nolint:noctx
	if err != nil {
		t.Fatalf("callback GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback returned %d, want 200", resp.StatusCode)
	}
	if capturedVerifier == "" {
		t.Error("token endpoint did not receive code_verifier (PKCE not used)")
	}

	// Step 4: Verify the token is stored and usable.
	tok, err := credStore.GetToken(ctx, backendName, testUserID)
	if err != nil || tok == nil {
		t.Fatalf("GetToken: tok=%v err=%v", tok, err)
	}
	if tok.AccessToken != accessToken {
		t.Errorf("access token: got %q, want %q", tok.AccessToken, accessToken)
	}

	// Simulate what CallTool does before the session call.
	callCtx := withUserID(ctx, testUserID)
	if storedTok, _ := credStore.GetToken(callCtx, backendName, testUserID); storedTok != nil && time.Now().Before(storedTok.Expiry) {
		callCtx = withOAuthToken(callCtx, storedTok.AccessToken)
	}
	if got := oauthTokenFromContext(callCtx); got != accessToken {
		t.Errorf("OAuth token in context: got %q, want %q", got, accessToken)
	}
}
