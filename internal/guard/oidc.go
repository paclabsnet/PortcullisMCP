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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const pkceStateExpiry = 10 * time.Minute

// OIDCManager handles OIDC Auth Code + PKCE discovery, login initiation,
// token exchange, and synchronous token refresh for Guard.
// Unlike Gate's manager it has no background refresh loop or state machine —
// refresh is performed on-demand by the auth middleware.
type OIDCManager struct {
	cfg IdentityConfig

	discoverMu    sync.Mutex
	authEndpoint  string
	tokenEndpoint string
}

// NewOIDCManager creates an OIDCManager from the guard identity configuration.
func NewOIDCManager(cfg IdentityConfig) *OIDCManager {
	return &OIDCManager{cfg: cfg}
}

// StartLogin generates PKCE parameters and returns the IdP authorization URL
// and the PKCEState to be stored in the AuthStore.
// returnPath is the same-origin path the user should be sent to after login.
func (m *OIDCManager) StartLogin(ctx context.Context, returnPath string) (authURL string, state PKCEState, err error) {
	if err := m.discover(ctx); err != nil {
		return "", PKCEState{}, fmt.Errorf("OIDC discovery: %w", err)
	}

	verifier, err := generateRandomString(64)
	if err != nil {
		return "", PKCEState{}, fmt.Errorf("generate code verifier: %w", err)
	}
	stateParam, err := generateRandomString(32)
	if err != nil {
		return "", PKCEState{}, fmt.Errorf("generate state: %w", err)
	}
	nonce, err := generateRandomString(32)
	if err != nil {
		return "", PKCEState{}, fmt.Errorf("generate nonce: %w", err)
	}

	ps := PKCEState{
		State:        stateParam,
		Nonce:        nonce,
		CodeVerifier: verifier,
		ReturnPath:   returnPath,
		ExpiresAt:    time.Now().Add(pkceStateExpiry),
	}

	scopes := m.cfg.Config.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {m.cfg.Config.Client.ID},
		"redirect_uri":          {m.cfg.Config.RedirectURI},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {stateParam},
		"nonce":                 {nonce},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}

	slog.Info("guard/oidc: started login flow", "auth_endpoint", m.authEndpoint)
	return m.authEndpoint + "?" + params.Encode(), ps, nil
}

// HandleCallback exchanges the authorization code for tokens, validates the
// nonce, and extracts the user's subject and display name from the ID token.
// Returns the token set, userID (sub claim), and displayName (name claim).
func (m *OIDCManager) HandleCallback(ctx context.Context, code, codeVerifier, nonce string) (*OIDCTokenSet, string, string, error) {
	tokens, err := m.exchangeCode(ctx, code, codeVerifier)
	if err != nil {
		return nil, "", "", fmt.Errorf("token exchange: %w", err)
	}

	claims, err := unsafeParseJWTClaims(tokens.IDToken)
	if err != nil {
		return nil, "", "", fmt.Errorf("parse id_token: %w", err)
	}

	gotNonce, _ := claims["nonce"].(string)
	if gotNonce != nonce {
		return nil, "", "", fmt.Errorf("id_token nonce mismatch")
	}

	userID, _ := claims["sub"].(string)
	if userID == "" {
		return nil, "", "", fmt.Errorf("id_token missing sub claim")
	}
	displayName, _ := claims["name"].(string)
	if displayName == "" {
		// Fall back to email if name is absent
		displayName, _ = claims["email"].(string)
	}
	if displayName == "" {
		displayName = userID
	}

	slog.Info("guard/oidc: login successful", "user_id", userID, "expiry", tokens.Expiry)
	return tokens, userID, displayName, nil
}

// DoRefresh performs a synchronous token refresh using the provided refresh token.
// Returns an error wrapping "invalid_grant" if the refresh token has expired or
// been revoked, which the caller should treat as a session termination.
func (m *OIDCManager) DoRefresh(ctx context.Context, refreshToken string) (*OIDCTokenSet, error) {
	if err := m.discover(ctx); err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}

	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {m.cfg.Config.Client.ID},
	}
	if m.cfg.Config.Client.Secret != "" {
		params.Set("client_secret", m.cfg.Config.Client.Secret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.tokenEndpoint,
		strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &errResp)
		detail := errResp.Error
		if errResp.ErrorDescription != "" {
			detail += ": " + errResp.ErrorDescription
		}
		return nil, fmt.Errorf("%s", detail) // preserve "invalid_grant" for caller check
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parse refresh response: %w", err)
	}

	expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	if tokenResp.ExpiresIn == 0 {
		expiry = time.Now().Add(1 * time.Hour)
	}

	// Some IdPs don't rotate the refresh token — keep the old one.
	newRefresh := tokenResp.RefreshToken
	if newRefresh == "" {
		newRefresh = refreshToken
	}

	return &OIDCTokenSet{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: newRefresh,
		IDToken:      tokenResp.IDToken,
		Expiry:       expiry,
	}, nil
}

// IsInvalidGrant reports whether the error indicates a revoked or expired
// refresh token (invalid_grant), meaning the session must be terminated.
func IsInvalidGrant(err error) bool {
	return err != nil && strings.Contains(err.Error(), "invalid_grant")
}

// discover fetches the OIDC discovery document and caches auth/token endpoints.
// Successful results are cached; failures are not, so the next call retries.
func (m *OIDCManager) discover(ctx context.Context) error {
	m.discoverMu.Lock()
	defer m.discoverMu.Unlock()

	if m.authEndpoint != "" && m.tokenEndpoint != "" {
		return nil
	}

	wellKnown := strings.TrimRight(m.cfg.Config.IssuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return fmt.Errorf("build discovery request: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch OIDC discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OIDC discovery returned %d", resp.StatusCode)
	}

	var doc struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("parse OIDC discovery: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return fmt.Errorf("OIDC discovery missing authorization_endpoint or token_endpoint")
	}

	m.authEndpoint = doc.AuthorizationEndpoint
	m.tokenEndpoint = doc.TokenEndpoint
	return nil
}

// exchangeCode performs the PKCE authorization code exchange.
func (m *OIDCManager) exchangeCode(ctx context.Context, code, codeVerifier string) (*OIDCTokenSet, error) {
	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {m.cfg.Config.RedirectURI},
		"client_id":     {m.cfg.Config.Client.ID},
		"code_verifier": {codeVerifier},
	}
	if m.cfg.Config.Client.Secret != "" {
		params.Set("client_secret", m.cfg.Config.Client.Secret)
	}

	// Testing hook: if _test_nonce is in the context, pass it to the token endpoint.
	if tn, ok := ctx.Value("_test_nonce").(string); ok {
		params.Set("_test_nonce", tn)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.tokenEndpoint,
		strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &errResp)
		detail := errResp.Error
		if errResp.ErrorDescription != "" {
			detail += ": " + errResp.ErrorDescription
		}
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, detail)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	if tokenResp.IDToken == "" {
		return nil, fmt.Errorf("token response missing id_token")
	}

	expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	if tokenResp.ExpiresIn == 0 {
		expiry = time.Now().Add(1 * time.Hour)
	}

	return &OIDCTokenSet{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		Expiry:       expiry,
	}, nil
}

// generateRandomString returns a URL-safe base64-encoded random string of n bytes.
func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceChallenge computes the S256 PKCE code challenge from a verifier.
func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// unsafeParseJWTClaims decodes the payload of a JWT without verifying the
// signature. Used only to extract display claims (sub, name, nonce).
func unsafeParseJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT: expected 3 parts, got %d", len(parts))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode jwt payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal jwt claims: %w", err)
	}
	return claims, nil
}
