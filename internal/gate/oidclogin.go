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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const defaultPKCESessionExpiry = 10 * time.Minute

// pkceSessionRecord is the on-disk representation of a PKCE session used in
// duplicate_mcp_hack mode. The secondary writes this file so the primary can
// complete the token exchange when it receives the OAuth callback.
type pkceSessionRecord struct {
	State        string    `json:"state"`
	CodeVerifier string    `json:"code_verifier"`
	Nonce        string    `json:"nonce"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// pkceSession holds the PKCE state for an in-flight login attempt.
type pkceSession struct {
	codeVerifier  string
	codeChallenge string
	state         string
	nonce         string
	expiresAt     time.Time
}

// OIDCTokenSet holds the tokens obtained from a successful OIDC login.
type OIDCTokenSet struct {
	AccessToken   string
	RefreshToken  string
	IDToken       string
	Expiry        time.Time
	RefreshExpiry time.Time // zero if unknown
}

// OIDCLoginManager manages the Auth Code + PKCE login flow for oidc-login source.
// It starts the login, handles the callback, stores tokens in memory, and
// refreshes the access token asynchronously before it expires.
type OIDCLoginManager struct {
	cfg               OIDCLoginConfig
	mgmtPort          int
	sm                *StateMachine
	identity          IdentitySource           // updated directly via SetToken on login/refresh
	onAuthenticated   func(rawIDToken string) // called when login completes (after identity update)
	onUnauthenticated func()                   // called when refresh token expires naturally
	onRefreshFailed   func(err error)          // called when refresh fails for non-expiry reasons

	mu          sync.Mutex
	sessions    map[string]*pkceSession // keyed by state param
	tokens      *OIDCTokenSet
	refreshStop chan struct{}

	// pkceSessionExpiry is the window a user has to complete the browser login
	// after StartLogin() returns the authorization URL. Derived from
	// login_callback_timeout_seconds; defaults to defaultPKCESessionExpiry.
	pkceSessionExpiry time.Duration

	// duplicate_mcp_hack file paths — empty unless duplicate_mcp_hack is enabled in config.
	pkceSessionFile string // secondary writes PKCE session here; primary reads to complete callback
	tokenCacheFile  string // primary writes JWT here after exchange/refresh; secondary polls this file

	// OIDC discovery — protected by discoverMu.
	// authEndpoint and tokenEndpoint are empty until a successful discovery.
	// Failed discovery attempts are not cached; the next StartLogin call retries.
	discoverMu    sync.Mutex
	authEndpoint  string
	tokenEndpoint string
}

// NewOIDCLoginManager creates an OIDCLoginManager.
// callbackTimeoutSecs is the window (in seconds) a user has to complete the
// browser login after StartLogin() is called. 0 uses the default (10 minutes).
// identity receives SetToken calls directly on login and token refresh.
func NewOIDCLoginManager(cfg OIDCLoginConfig, mgmtPort int, callbackTimeoutSecs int, sm *StateMachine,
	identity IdentitySource,
	onAuthenticated func(string), onUnauthenticated func(), onRefreshFailed func(error)) *OIDCLoginManager {
	expiry := defaultPKCESessionExpiry
	if callbackTimeoutSecs > 0 {
		expiry = time.Duration(callbackTimeoutSecs) * time.Second
	}
	return &OIDCLoginManager{
		cfg:               cfg,
		mgmtPort:          mgmtPort,
		sm:                sm,
		identity:          identity,
		onAuthenticated:   onAuthenticated,
		onUnauthenticated: onUnauthenticated,
		onRefreshFailed:   onRefreshFailed,
		sessions:          make(map[string]*pkceSession),
		pkceSessionExpiry: expiry,
		pkceSessionFile:   cfg.PKCESessionFile,
		tokenCacheFile:    cfg.TokenCacheFile,
	}
}

// discover fetches OIDC discovery document and caches auth/token endpoints.
// If a previous attempt succeeded, it returns immediately with the cached
// values. If a previous attempt failed, the result is NOT cached and the next
// call will retry — this avoids the sync.Once pitfall where a transient network
// error at startup permanently prevents discovery.
func (m *OIDCLoginManager) discover(ctx context.Context) error {
	m.discoverMu.Lock()
	defer m.discoverMu.Unlock()

	// Already discovered successfully.
	if m.authEndpoint != "" && m.tokenEndpoint != "" {
		return nil
	}

	wellKnown := strings.TrimRight(m.cfg.IssuerURL, "/") + "/.well-known/openid-configuration"
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
	// Only cache on complete success — partial writes avoided by assigning both together.
	m.authEndpoint = doc.AuthorizationEndpoint
	m.tokenEndpoint = doc.TokenEndpoint
	return nil
}

// StartLogin generates a PKCE session and returns the authorization URL.
// It also sets the state machine to StateAuthenticating.
func (m *OIDCLoginManager) StartLogin(ctx context.Context) (string, error) {
	if err := m.discover(ctx); err != nil {
		return "", fmt.Errorf("OIDC discovery: %w", err)
	}

	// Generate PKCE code verifier and challenge
	verifier, err := generateRandomString(64)
	if err != nil {
		return "", fmt.Errorf("generate code verifier: %w", err)
	}
	challenge := pkceChallenge(verifier)

	// Generate state and nonce
	state, err := generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	nonce, err := generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	// Store session
	session := &pkceSession{
		codeVerifier:  verifier,
		codeChallenge: challenge,
		state:         state,
		nonce:         nonce,
		expiresAt:     time.Now().Add(m.pkceSessionExpiry),
	}
	m.mu.Lock()
	// Clean up expired sessions
	for k, s := range m.sessions {
		if time.Now().After(s.expiresAt) {
			delete(m.sessions, k)
		}
	}
	m.sessions[state] = session
	m.mu.Unlock()

	// In duplicate_mcp_hack mode, write the PKCE session to disk so the primary
	// instance can complete the token exchange when it receives the callback.
	m.writePKCESessionFile(session)

	// Build redirect URI
	redirectURI := m.redirectURI()

	// Build authorization URL
	scopes := m.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {m.cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authURL := m.authEndpoint + "?" + params.Encode()

	m.sm.SetAuthenticating()
	slog.Info("oidc-login: started login flow", "auth_url_base", m.authEndpoint)
	return authURL, nil
}

// HandleCallback processes the OIDC callback, exchanges the code for tokens,
// and transitions the state machine to authenticated.
// Returns an error string to show in the callback page, or nil on success.
func (m *OIDCLoginManager) HandleCallback(ctx context.Context, queryState, code, errParam, errDesc string) error {
	if errParam != "" {
		detail := errParam
		if errDesc != "" {
			detail += ": " + errDesc
		}
		m.sm.SetSystemError(SubstateInvalid, "IdP returned an error", "IdP error: "+detail)
		return fmt.Errorf("IdP returned error: %s", detail)
	}

	if queryState == "" || code == "" {
		m.sm.SetSystemError(SubstateInvalid, "Invalid callback", "Missing state or code in callback")
		return fmt.Errorf("missing state or code in callback")
	}

	m.mu.Lock()
	session, ok := m.sessions[queryState]
	if ok {
		delete(m.sessions, queryState)
	}
	m.mu.Unlock()

	if ok && m.pkceSessionFile != "" {
		// Primary handled this callback from its own in-memory session. Clean up
		// any on-disk PKCE session written when this login was initiated, so
		// sensitive verifier/nonce data is not left on disk until expiry.
		if _, cleanErr := m.readAndConsumePKCESessionFile(queryState); cleanErr == nil {
			slog.Debug("duplicate-mcp-hack: cleaned up PKCE session file after primary-handled callback")
		}
	}

	if !ok && m.pkceSessionFile != "" {
		// In duplicate_mcp_hack mode, try the on-disk PKCE session written by the
		// secondary instance. The primary (which owns the callback port) reads
		// it here to complete the exchange on the secondary's behalf.
		fileSession, fileErr := m.readAndConsumePKCESessionFile(queryState)
		if fileErr == nil {
			session = fileSession
			ok = true
			slog.Info("duplicate-mcp-hack: completing token exchange using PKCE session file")
		} else {
			slog.Debug("duplicate-mcp-hack: pkce session file not usable", "error", fileErr)
		}
	}

	if !ok {
		m.sm.SetSystemError(SubstateInvalid, "Invalid login session", "Unknown or expired state parameter")
		return fmt.Errorf("unknown or expired state parameter")
	}
	if time.Now().After(session.expiresAt) {
		m.sm.SetSystemError(SubstateInvalid, "Login session expired", "Login session timed out")
		return fmt.Errorf("login session expired")
	}

	// Exchange code for tokens
	tokens, err := m.exchangeCode(ctx, code, session.codeVerifier)
	if err != nil {
		m.sm.SetSystemError(SubstateInvalid, "Token exchange failed", err.Error())
		return fmt.Errorf("token exchange: %w", err)
	}

	// Validate nonce in ID token
	if err := m.validateNonce(tokens.IDToken, session.nonce); err != nil {
		m.sm.SetSystemError(SubstateInvalid, "Nonce validation failed", err.Error())
		return fmt.Errorf("nonce validation: %w", err)
	}

	m.mu.Lock()
	// Stop any existing refresh cycle
	if m.refreshStop != nil {
		close(m.refreshStop)
	}
	m.tokens = tokens
	m.refreshStop = make(chan struct{})
	stopCh := m.refreshStop
	m.mu.Unlock()

	m.sm.SetAuthenticated()
	slog.Info("oidc-login: login successful", "expiry", tokens.Expiry)

	// In duplicate_mcp_hack mode, write the token file so the secondary instance
	// can pick it up via its file poller.
	m.writeTokenFile(tokens.IDToken)

	// Update identity directly via the IdentitySource interface.
	if m.identity != nil {
		if err := m.identity.SetToken(tokens.IDToken); err != nil {
			slog.Warn("oidc-login: failed to update identity on login", "error", err)
		}
	}

	// Notify caller for any additional side effects (e.g. refreshing tool list).
	if m.onAuthenticated != nil {
		m.onAuthenticated(tokens.IDToken)
	}

	// Start async refresh cycle
	go m.refreshLoop(tokens, stopCh)

	return nil
}

// GetTokens returns the current token set (nil if not authenticated).
func (m *OIDCLoginManager) GetTokens() *OIDCTokenSet {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tokens
}

func (m *OIDCLoginManager) redirectURI() string {
	if m.cfg.RedirectURI != "" {
		return m.cfg.RedirectURI
	}
	port := m.mgmtPort
	if port == 0 {
		port = DefaultManagementAPIPort
	}
	return fmt.Sprintf("http://localhost:%d/auth/callback", port)
}

// exchangeCode performs the PKCE token exchange.
func (m *OIDCLoginManager) exchangeCode(ctx context.Context, code, codeVerifier string) (*OIDCTokenSet, error) {
	params := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {m.redirectURI()},
		"client_id":     {m.cfg.ClientID},
		"code_verifier": {codeVerifier},
	}
	if m.cfg.ClientSecret != "" {
		params.Set("client_secret", m.cfg.ClientSecret)
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
		expiry = time.Now().Add(1 * time.Hour) // safe default
	}

	return &OIDCTokenSet{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		Expiry:       expiry,
	}, nil
}

// validateNonce verifies the nonce claim in the ID token without signature verification.
func (m *OIDCLoginManager) validateNonce(idToken, expectedNonce string) error {
	claims, err := unsafeParseJWTClaims(idToken)
	if err != nil {
		return fmt.Errorf("parse id_token claims: %w", err)
	}
	nonce, _ := claims["nonce"].(string)
	if nonce != expectedNonce {
		return fmt.Errorf("id_token nonce mismatch")
	}
	return nil
}

// refreshLoop runs as a goroutine, refreshing the access token before expiry.
// It uses timing: refresh at expiry - max(60s, lifetime * 0.1).
func (m *OIDCLoginManager) refreshLoop(initial *OIDCTokenSet, stop <-chan struct{}) {
	tokens := initial
	for {
		lifetime := time.Until(tokens.Expiry)
		slack := time.Duration(float64(lifetime) * 0.1)
		if slack < 60*time.Second {
			slack = 60 * time.Second
		}
		refreshIn := lifetime - slack
		if refreshIn <= 0 {
			refreshIn = 5 * time.Second
		}

		slog.Debug("oidc-login: next token refresh scheduled", "in", refreshIn.Round(time.Second))

		select {
		case <-stop:
			slog.Debug("oidc-login: refresh loop stopped")
			return
		case <-time.After(refreshIn):
		}

		newTokens, err := m.doRefresh()
		if err != nil {
			// Check if this is a natural refresh token expiry (invalid_grant)
			if isInvalidGrant(err) {
				slog.Info("oidc-login: refresh token expired naturally; returning to unauthenticated state")
				m.mu.Lock()
				m.tokens = nil
				m.mu.Unlock()
				m.sm.SetUnauthenticated()
				m.deleteTokenFile()
				if m.onUnauthenticated != nil {
					m.onUnauthenticated()
				}
				return
			}
			slog.Error("oidc-login: token refresh failed", "error", err)
			m.mu.Lock()
			m.tokens = nil
			m.mu.Unlock()
			m.sm.SetSystemError(SubstateRefreshFailed, "Token refresh failed", err.Error())
			m.deleteTokenFile()
			if m.onRefreshFailed != nil {
				m.onRefreshFailed(err)
			}
			return
		}

		m.mu.Lock()
		m.tokens = newTokens
		m.mu.Unlock()

		// In duplicate_mcp_hack mode, update the token file so the secondary picks
		// up the refreshed token via its file poller.
		if newTokens.IDToken != "" {
			m.writeTokenFile(newTokens.IDToken)
		}

		// Update identity directly on refresh.
		if m.identity != nil && newTokens.IDToken != "" {
			if err := m.identity.SetToken(newTokens.IDToken); err != nil {
				slog.Warn("oidc-login: failed to update identity on refresh", "error", err)
			}
		}

		// Notify caller for any additional side effects.
		if m.onAuthenticated != nil && newTokens.IDToken != "" {
			m.onAuthenticated(newTokens.IDToken)
		}

		tokens = newTokens
		slog.Info("oidc-login: token refreshed successfully", "expiry", tokens.Expiry)
	}
}

// doRefresh performs a token refresh using the current refresh token.
func (m *OIDCLoginManager) doRefresh() (*OIDCTokenSet, error) {
	m.mu.Lock()
	if m.tokens == nil || m.tokens.RefreshToken == "" {
		m.mu.Unlock()
		return nil, fmt.Errorf("no refresh token available")
	}
	refreshToken := m.tokens.RefreshToken
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {m.cfg.ClientID},
	}
	if m.cfg.ClientSecret != "" {
		params.Set("client_secret", m.cfg.ClientSecret)
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
		return nil, fmt.Errorf("%s", detail) // keep error text for isInvalidGrant check
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

	// Some IdPs don't return a new refresh token — keep the old one.
	newRefresh := tokenResp.RefreshToken
	if newRefresh == "" {
		newRefresh = refreshToken
	}

	// Use new ID token if provided; otherwise keep current for identity update.
	idToken := tokenResp.IDToken
	if idToken == "" {
		m.mu.Lock()
		if m.tokens != nil {
			idToken = m.tokens.IDToken
		}
		m.mu.Unlock()
	}

	return &OIDCTokenSet{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: newRefresh,
		IDToken:      idToken,
		Expiry:       expiry,
	}, nil
}

// writePKCESessionFile writes the PKCE session to disk in duplicate_mcp_hack mode
// so the primary instance can complete the token exchange on callback.
// Called after m.mu is released. Failures are logged as warnings only.
func (m *OIDCLoginManager) writePKCESessionFile(session *pkceSession) {
	if m.pkceSessionFile == "" {
		return
	}
	path, err := expandHome(m.pkceSessionFile)
	if err != nil {
		slog.Warn("duplicate-mcp-hack: failed to expand pkce session file path", "error", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		slog.Warn("duplicate-mcp-hack: failed to create pkce session directory", "error", err)
		return
	}
	rec := pkceSessionRecord{
		State:        session.state,
		CodeVerifier: session.codeVerifier,
		Nonce:        session.nonce,
		ExpiresAt:    session.expiresAt,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		slog.Warn("duplicate-mcp-hack: failed to marshal pkce session", "error", err)
		return
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		slog.Warn("duplicate-mcp-hack: failed to write pkce session file", "error", err)
		return
	}
	slog.Debug("duplicate-mcp-hack: wrote PKCE session file")
}

// readAndConsumePKCESessionFile reads the on-disk PKCE session file, validates
// the state, deletes the file immediately (regardless of exchange outcome), and
// returns a pkceSession suitable for completing the token exchange.
// Called from HandleCallback when the state is not found in memory.
func (m *OIDCLoginManager) readAndConsumePKCESessionFile(queryState string) (*pkceSession, error) {
	path, err := expandHome(m.pkceSessionFile)
	if err != nil {
		return nil, fmt.Errorf("expand pkce session file path: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pkce session file: %w", err)
	}
	var rec pkceSessionRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("parse pkce session file: %w", err)
	}
	if rec.State != queryState {
		return nil, fmt.Errorf("pkce session file state mismatch")
	}
	if time.Now().After(rec.ExpiresAt) {
		return nil, fmt.Errorf("pkce session file expired")
	}
	// Delete immediately to minimise the exposure window, even if the
	// subsequent token exchange fails.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		slog.Warn("duplicate-mcp-hack: failed to delete PKCE session file after consumption", "error", err)
	}
	return &pkceSession{
		codeVerifier: rec.CodeVerifier,
		state:        rec.State,
		nonce:        rec.Nonce,
		expiresAt:    rec.ExpiresAt,
	}, nil
}

// writeTokenFile writes the OIDC ID token to the token cache file in
// duplicate_mcp_hack mode. The secondary instance polls this file to authenticate.
// Failures are logged as warnings only — the in-memory token is unaffected.
func (m *OIDCLoginManager) writeTokenFile(idToken string) {
	if m.tokenCacheFile == "" || idToken == "" {
		return
	}
	path, err := expandHome(m.tokenCacheFile)
	if err != nil {
		slog.Warn("duplicate-mcp-hack: failed to expand token cache file path", "error", err)
		return
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		slog.Warn("duplicate-mcp-hack: failed to create token cache directory", "error", err)
		return
	}
	// Atomic write: create a temp file in the same directory, write, then rename.
	// This prevents the poller from reading a partial token during an in-place overwrite.
	tmp, err := os.CreateTemp(dir, ".oidc-token-*.tmp")
	if err != nil {
		slog.Warn("duplicate-mcp-hack: failed to create temp token file", "error", err)
		return
	}
	tmpPath := tmp.Name()
	_, werr := fmt.Fprintf(tmp, "%s\n", idToken)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmpPath)
		slog.Warn("duplicate-mcp-hack: failed to write token cache file", "error", werr)
		return
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		slog.Warn("duplicate-mcp-hack: failed to rename token cache file", "error", err)
		return
	}
	slog.Debug("duplicate-mcp-hack: token cache file updated")
}

// deleteTokenFile removes the token cache file in duplicate_mcp_hack mode, signalling
// to the secondary instance that the session has ended and it should return to
// the unauthenticated state.
func (m *OIDCLoginManager) deleteTokenFile() {
	if m.tokenCacheFile == "" {
		return
	}
	path, err := expandHome(m.tokenCacheFile)
	if err != nil {
		return
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		slog.Warn("duplicate-mcp-hack: failed to delete token cache file", "error", err)
		return
	}
	slog.Info("duplicate-mcp-hack: token file deleted; secondary instance will return to unauthenticated state")
}

// isInvalidGrant reports whether an error string contains "invalid_grant",
// which indicates natural refresh token expiry.
func isInvalidGrant(err error) bool {
	return err != nil && strings.Contains(err.Error(), "invalid_grant")
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
