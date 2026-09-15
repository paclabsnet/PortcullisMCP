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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
	"github.com/paclabsnet/PortcullisMCP/internal/version"
)

// MCPBackend routes tool calls to a registered MCP backend server.
type MCPBackend interface {
	CallTool(ctx context.Context, serverName, toolName string, args map[string]any) (*mcp.CallToolResult, error)
	ListTools(ctx context.Context, serverName string) ([]*mcp.Tool, error)
}

// Router maintains MCP client sessions to all registered backend servers.
type Router struct {
	mu            sync.Mutex
	backends      map[string]*backendConn
	cacheMu       sync.RWMutex
	toolCache     []shared.AnnotatedTool
	exchangeMu    sync.RWMutex
	exchangers    map[string]IdentityExchanger
	storageConfig cfgloader.StorageConfig
	credStoreMu   sync.RWMutex
	credStore     CredentialsStore
	dcrGroup      singleflight.Group // deduplicate concurrent DCR attempts per backend
}

type backendConn struct {
	cfgMu       sync.RWMutex
	cfg         BackendConfig
	client      *mcp.Client
	session     *mcp.ClientSession
	aliasToReal map[string]string // alias → real backend tool name; nil if no aliases
}

// NewRouter creates a Router from the backend configs but does not yet connect.
// Connections are established lazily on first use. Exchange clients are built
// during the first Reload call (which Server.Run issues before accepting connections).
// An optional StorageConfig may be provided to enable Redis-backed token caching for
// identity exchange; if omitted an in-memory cache is used.
func NewRouter(backends []BackendConfig, storage ...cfgloader.StorageConfig) *Router {
	r := &Router{
		backends:   make(map[string]*backendConn, len(backends)),
		exchangers: make(map[string]IdentityExchanger, len(backends)),
	}
	if len(storage) > 0 {
		r.storageConfig = storage[0]
	}
	for _, cfg := range backends {
		r.backends[cfg.Name] = &backendConn{cfg: cfg}
		// Seed exchangers conservatively: backends with an exchange URL start as
		// failDegraded (safe) until the first Reload builds the real client; backends
		// without an exchange URL start as noop.
		if cfg.UserIdentity.Exchange.URL != "" {
			r.exchangers[cfg.Name] = failDegradedExchanger{backendName: cfg.Name}
		} else {
			r.exchangers[cfg.Name] = noopIdentityExchanger{}
		}
	}
	return r
}

// SetCredentialsStore attaches a CredentialsStore to the Router for OAuth token
// lookups and pending-flow state management.
func (r *Router) SetCredentialsStore(cs CredentialsStore) {
	r.credStoreMu.Lock()
	r.credStore = cs
	r.credStoreMu.Unlock()
}

// getCredStore returns the configured CredentialsStore or nil if not set.
func (r *Router) getCredStore() CredentialsStore {
	r.credStoreMu.RLock()
	cs := r.credStore
	r.credStoreMu.RUnlock()
	return cs
}

// CallTool routes a tool call to the named backend server.
// toolName is the alias as seen by the agent and PDP; it is un-aliased to the
// real backend tool name before dispatch so the PDP always evaluates the alias.
func (r *Router) CallTool(ctx context.Context, serverName, toolName string, args map[string]any) (*mcp.CallToolResult, error) {
	ctx, span := otel.Tracer(shared.ServiceKeep).Start(ctx, "keep.backend.call_tool")
	defer span.End()
	span.SetAttributes(
		attribute.String("backend.name", serverName),
		attribute.String("tool.name", toolName),
	)

	backendToolName := r.resolveToolName(serverName, toolName)
	identityType := r.backendType(serverName)

	// Apply identity exchange only for exchange-style backends (type "" or "exchange").
	// For "none", "api_key", and "oauth" the raw token must never be forwarded or
	// wrapped as an injected identity; skip the exchanger entirely for those types.
	if identityType == "" || identityType == "exchange" {
		ctx = r.applyIdentityExchange(ctx, serverName)
	}

	// For OAuth backends, pre-fetch a valid token from the CredentialsStore and
	// stash it in the context so the RoundTripper can inject it as a Bearer header.
	// If the token is within the configured refresh window, proactively refresh it
	// now so that the backend never sees a token that is about to expire mid-request.
	if identityType == "oauth" {
		userID := userIDFromContext(ctx)
		slog.Debug("keep: oauth token lookup", "backend", serverName, "user_id", userID)
		if userID != "" {
			if cs := r.getCredStore(); cs != nil {
				tok, err := cs.GetToken(ctx, serverName, userID)
				if err != nil {
					slog.Debug("keep: oauth token lookup error", "backend", serverName, "error", err)
				} else if tok == nil {
					slog.Debug("keep: oauth token not found in store (flow not yet completed)", "backend", serverName, "user_id", userID)
				} else {
					debugLogOAuthToken("keep: oauth token found in store", tok, "backend", serverName, "user_id", userID)
					// Treat a zero Expiry (no expires_in in the token response) as valid
					// indefinitely — RFC 6749 permits servers to omit expires_in.
					tokenValid := tok.Expiry.IsZero() || time.Now().Before(tok.Expiry)
					slog.Debug("keep: oauth token validity check",
						"backend", serverName,
						"expiry", tok.Expiry,
						"expiry_is_zero", tok.Expiry.IsZero(),
						"now", time.Now(),
						"valid", tokenValid,
					)
					if tokenValid {
						tok = r.maybeRefreshToken(ctx, serverName, userID, tok)
						ctx = withOAuthToken(ctx, tok.AccessToken)
						slog.Debug("keep: oauth token injected into context", "backend", serverName, "user_id", userID)
					} else if tok.RefreshToken != "" {
						// Token is expired but a refresh token is available — attempt silent
						// recovery before forcing the user through the browser OAuth flow again.
						if oauthCfg := r.backendOAuthCfg(serverName); oauthCfg != nil {
							if refreshed, rErr := r.refreshOAuthToken(ctx, serverName, userID, tok, *oauthCfg); rErr == nil {
								ctx = withOAuthToken(ctx, refreshed.AccessToken)
								slog.Debug("keep: expired token recovered via refresh; oauth token injected", "backend", serverName, "user_id", userID)
							} else {
								slog.Warn("keep: expired token refresh failed; will trigger new OAuth flow", "backend", serverName, "user_id", userID, "error", rErr)
							}
						} else {
							slog.Debug("keep: oauth token expired; will trigger new OAuth flow", "backend", serverName, "user_id", userID, "expiry", tok.Expiry)
						}
					} else {
						slog.Debug("keep: oauth token expired; will trigger new OAuth flow", "backend", serverName, "user_id", userID, "expiry", tok.Expiry)
					}
				}
			}
		}
	}

	// Apply identity path injection before dispatch for exchange-style backends only.
	// Type "none" suppresses all injection; "api_key" and "oauth" use their own
	// injection paths and must not additionally inject via json_path.
	// A shallow copy of args is created so the original map (referenced by the async
	// decision log) is never mutated.
	if identityType == "" || identityType == "exchange" {
		if identityPath := r.identityPathFor(serverName); identityPath != "" {
			if identity := exchangedIdentityFromContext(ctx); identity != nil {
				argsCopy := make(map[string]any, len(args))
				for k, v := range args {
					argsCopy[k] = v
				}
				if identity.Structured != nil {
					injectAtPath(argsCopy, identityPath, identity.Structured)
					slog.Info("keep: injected identity into tool arguments", "backend", serverName, "tool", toolName, "json_path", identityPath, "type", "structured")
				} else {
					injectAtPath(argsCopy, identityPath, identity.Str)
					slog.Info("keep: injected identity into tool arguments", "backend", serverName, "tool", toolName, "json_path", identityPath, "type", "string")
				}
				args = argsCopy
			} else {
				slog.Warn("keep: identity injection configured but no identity token in context — skipping json_path injection", "backend", serverName, "tool", toolName, "json_path", identityPath)
			}
		}
	}

	// Inject a capture struct so the RoundTripper can record the HTTP status and
	// response headers if the backend returns a non-2xx response. This lets us
	// return a structured CallToolResult (isError: true) with the headers intact
	// rather than a generic error that discards useful auth information.
	// This must be set before sessionFor so that a 401 during MCP initialize
	// (e.g. when the backend requires OAuth before the handshake) is also captured.
	ctx, respCap := withBackendRespCapture(ctx)

	session, err := r.sessionFor(ctx, serverName)
	if err != nil {
		// A 401 during session establishment (MCP initialize) must trigger the
		// same OAuth flow as a 401 from a tool call. Check the capture.
		respCap.mu.Lock()
		initStatus := respCap.statusCode
		initHeaders := respCap.headers
		respCap.mu.Unlock()

		if initStatus == http.StatusUnauthorized && r.backendType(serverName) == "oauth" {
			userID := userIDFromContext(ctx)
			oauthCfg := r.backendOAuthCfg(serverName)
			if oauthCfg != nil {
				wwwAuth := initHeaders.Get("WWW-Authenticate")
				eps, discErr := resolveOAuthEndpoints(ctx, *oauthCfg, wwwAuth)
				if discErr != nil {
					slog.Warn("keep: OAuth endpoint discovery failed after initialize 401", "backend", serverName, "error", discErr)
				} else {
					authResult, flowErr := r.tryStartOAuthFlow(ctx, serverName, userID, eps)
					if flowErr != nil {
						slog.Warn("keep: failed to start OAuth flow after initialize 401", "backend", serverName, "error", flowErr)
					} else {
						span.SetStatus(codes.Error, "oauth flow required")
						return authResult, nil
					}
				}
			}
		}

		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	debugLogMCPCall(serverName, backendToolName, args)
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      backendToolName,
		Arguments: args,
	})
	if err != nil {
		slog.Debug("keep: MCP← tool call error", "backend", serverName, "tool", backendToolName, "error", err)
	} else if result != nil {
		debugLogMCPResult(serverName, backendToolName, result.IsError, result.Content)
	}
	if err != nil && isDeadSessionError(err) {
		// The cached session is dead (SSE stream dropped, server-side timeout, etc.).
		// Drop it and retry once with a fresh session.
		slog.Warn("keep: MCP session appears dead; dropping and reconnecting", "backend", serverName, "error", err)
		r.dropSession(serverName)
		if session2, sessErr := r.sessionFor(ctx, serverName); sessErr == nil {
			debugLogMCPCall(serverName, backendToolName, args)
			result, err = session2.CallTool(ctx, &mcp.CallToolParams{
				Name:      backendToolName,
				Arguments: args,
			})
			if err != nil {
				slog.Debug("keep: MCP← tool call error (retry)", "backend", serverName, "tool", backendToolName, "error", err)
			} else if result != nil {
				debugLogMCPResult(serverName, backendToolName, result.IsError, result.Content)
			}
		} else {
			slog.Warn("keep: reconnect after dead session failed", "backend", serverName, "error", sessErr)
		}
	}
	if err != nil {
		// If the backend sent a non-2xx HTTP response, surface the status and
		// headers to the agent as a structured error result so it can act on
		// them (e.g. a 401 with WWW-Authenticate tells it how to re-authenticate).
		respCap.mu.Lock()
		statusCode := respCap.statusCode
		headers := respCap.headers
		respCap.mu.Unlock()
		if statusCode != 0 {
			// For OAuth backends a 401 means the stored token is missing or
			// expired.  Initiate a new authorization flow and return the auth
			// URL to the agent so it can prompt the user.
			if statusCode == http.StatusUnauthorized && r.backendType(serverName) == "oauth" {
				userID := userIDFromContext(ctx)
				oauthCfg := r.backendOAuthCfg(serverName)
				if oauthCfg == nil {
					slog.Warn("keep: OAuth config missing for backend after 401", "backend", serverName)
				} else {
					wwwAuth := headers.Get("WWW-Authenticate")
					eps, discErr := resolveOAuthEndpoints(ctx, *oauthCfg, wwwAuth)
					if discErr != nil {
						slog.Warn("keep: OAuth endpoint discovery failed after 401", "backend", serverName, "error", discErr)
						// Fall through to generic error path.
					} else {
						authResult, flowErr := r.tryStartOAuthFlow(ctx, serverName, userID, eps)
						if flowErr != nil {
							slog.Warn("keep: failed to start OAuth flow after 401", "backend", serverName, "error", flowErr)
							// Fall through to the generic error path below.
						} else {
							span.SetStatus(codes.Error, "oauth flow required")
							return authResult, nil
						}
					}
				}
			}

			var sb strings.Builder
			fmt.Fprintf(&sb, "Backend returned HTTP %d %s\n", statusCode, http.StatusText(statusCode))
			for k, vs := range headers {
				for _, v := range vs {
					fmt.Fprintf(&sb, "%s: %s\n", k, v)
				}
			}
			span.SetStatus(codes.Error, fmt.Sprintf("backend HTTP %d", statusCode))
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: strings.TrimRight(sb.String(), "\n")}},
			}, nil
		}
		span.SetStatus(codes.Error, err.Error())
	}
	return result, err
}

// backendType returns the UserIdentity.Type for the named backend, or "" if unknown.
func (r *Router) backendType(serverName string) string {
	r.mu.Lock()
	conn, ok := r.backends[serverName]
	r.mu.Unlock()
	if !ok {
		return ""
	}
	conn.cfgMu.RLock()
	t := conn.cfg.UserIdentity.Type
	conn.cfgMu.RUnlock()
	return t
}

// backendOAuthCfg returns a copy of the BackendOAuth config for the named backend,
// or nil if the backend is not found or is not of type "oauth".
func (r *Router) backendOAuthCfg(serverName string) *BackendOAuth {
	r.mu.Lock()
	conn, ok := r.backends[serverName]
	r.mu.Unlock()
	if !ok {
		return nil
	}
	conn.cfgMu.RLock()
	defer conn.cfgMu.RUnlock()
	if conn.cfg.UserIdentity.Type != "oauth" {
		return nil
	}
	cfg := conn.cfg.UserIdentity.OAuth
	return &cfg
}

// maybeRefreshToken returns a (possibly refreshed) token. If the token is still
// valid but within the configured refresh window and a refresh token is available,
// it calls refreshOAuthToken and returns the new token on success. On refresh
// failure the original token is returned so the request can still proceed with
// the current access token (fail-degraded).
func (r *Router) maybeRefreshToken(ctx context.Context, serverName, userID string, tok *userToken) *userToken {
	oauthCfg := r.backendOAuthCfg(serverName)
	if oauthCfg == nil {
		return tok
	}
	rw := oauthCfg.RefreshWindow()
	if rw <= 0 || tok.RefreshToken == "" {
		return tok
	}
	// No expiry info means the server didn't set expires_in; skip proactive refresh.
	if tok.Expiry.IsZero() {
		return tok
	}
	if time.Until(tok.Expiry) >= rw {
		return tok // outside window; no refresh needed yet
	}
	refreshed, err := r.refreshOAuthToken(ctx, serverName, userID, tok, *oauthCfg)
	if err != nil {
		slog.Warn("keep: proactive OAuth token refresh failed; using existing token",
			"backend", serverName, "user_id", userID, "error", err)
		return tok
	}
	return refreshed
}

// refreshOAuthToken performs a refresh-token grant and stores the resulting token.
// It uses golang.org/x/oauth2 for the HTTP exchange. The current access token is
// marked as expired before passing it to the token source so that oauth2 always
// performs a network round-trip rather than returning the cached value.
// If StoreRefreshTokens is false the refresh token is stripped before storage.
func (r *Router) refreshOAuthToken(ctx context.Context, serverName, userID string, current *userToken, oauthCfg BackendOAuth) (*userToken, error) {
	if current.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token stored for backend %q user %q", serverName, userID)
	}

	// Prefer dynamic client credentials when available.
	clientID := oauthCfg.ClientID
	clientSecret := ""
	if cs := r.getCredStore(); cs != nil {
		if reg, err := cs.GetClientReg(ctx, serverName); err == nil && reg != nil {
			clientID = reg.ClientID
			clientSecret = reg.ClientSecret
		}
	}

	// Prefer the endpoint that was discovered during the original OAuth flow and
	// persisted with the token; fall back to the static config value.
	tokenEndpoint := current.TokenEndpoint
	if tokenEndpoint == "" {
		tokenEndpoint = oauthCfg.TokenEndpoint
	}

	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: tokenEndpoint,
		},
	}

	// Mark the token as already expired so oauth2 always issues the refresh grant.
	stale := &oauth2.Token{
		AccessToken:  current.AccessToken,
		RefreshToken: current.RefreshToken,
		Expiry:       time.Now().Add(-time.Second),
	}
	newTok, err := cfg.TokenSource(ctx, stale).Token()
	if err != nil {
		return nil, fmt.Errorf("refresh token grant for backend %q: %w", serverName, err)
	}

	ut := &userToken{
		AccessToken:  newTok.AccessToken,
		RefreshToken: newTok.RefreshToken,
		Expiry:       newTok.Expiry,
	}
	if !oauthCfg.StoreRefreshTokens {
		ut.RefreshToken = ""
	}

	if cs := r.getCredStore(); cs != nil {
		if err := cs.SetToken(ctx, serverName, userID, ut); err != nil {
			slog.Warn("keep: failed to persist refreshed OAuth token", "backend", serverName, "user_id", userID, "error", err)
		}
	}
	slog.Info("keep: proactively refreshed OAuth token", "backend", serverName, "user_id", userID)
	return ut, nil
}

// tryStartOAuthFlow generates a PKCE authorization URL for the named backend
// and returns a CallToolResult that instructs the agent to prompt the user to
// visit the URL.  The pending PKCE state is stored in the CredentialsStore.
// eps contains the authorization and token endpoint URLs resolved by the caller
// (via resolveOAuthEndpoints) so discovery is not repeated inside this function.
func (r *Router) tryStartOAuthFlow(ctx context.Context, serverName, userID string, eps oauthEndpoints) (*mcp.CallToolResult, error) {
	r.mu.Lock()
	conn, ok := r.backends[serverName]
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("unknown backend %q", serverName)
	}

	conn.cfgMu.RLock()
	oauthCfg := conn.cfg.UserIdentity.OAuth
	conn.cfgMu.RUnlock()

	cs := r.getCredStore()
	if cs == nil {
		return nil, fmt.Errorf("no credentials store configured")
	}

	// Resolve the client ID and effective scopes.
	// For dynamic clients the clientReg takes precedence; for static clients
	// we fall back to the configured ClientID and Scopes.
	clientID, effectiveScopes, err := r.resolveOAuthClientCredentials(ctx, serverName, oauthCfg, eps, cs)
	if err != nil {
		return nil, err
	}

	codeVerifier, err := generatePKCEVerifier()
	if err != nil {
		return nil, fmt.Errorf("generate pkce verifier: %w", err)
	}
	codeChallenge := pkceChallenge(codeVerifier)

	nonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	pending := &pendingAuth{
		CodeVerifier:  codeVerifier,
		BackendName:   serverName,
		UserID:        userID,
		TokenEndpoint: eps.TokenEndpoint,
		ClientID:      clientID,
		RedirectURI:   oauthCfg.CallbackURL,
		Resource:      eps.Resource, // RFC 8707: carried into the token exchange
	}

	if err := cs.StorePending(ctx, nonce, pending, oauthCfg.FlowTimeout()); err != nil {
		return nil, fmt.Errorf("store pending auth: %w", err)
	}

	authURL := buildAuthURL(eps.AuthorizationEndpoint, clientID, oauthCfg.CallbackURL, effectiveScopes, nonce, codeChallenge, eps.Resource)
	slog.Info("keep: OAuth flow initiated", "backend", serverName, "user_id", userID)

	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{
			Text: fmt.Sprintf("Authentication required for backend %q. Please open the following URL to authorize:\n\n%s\n\nAfter authorizing, retry the request.", serverName, authURL),
		}},
	}, nil
}

// resolveOAuthClientCredentials returns the client_id and effective scopes to use
// for an OAuth flow. If DCR is enabled and no valid registration exists, it
// performs dynamic client registration (with singleflight + distributed locking
// to avoid thundering-herd and protect single-use Initial Access Tokens).
func (r *Router) resolveOAuthClientCredentials(ctx context.Context, serverName string, oauthCfg BackendOAuth, eps oauthEndpoints, cs CredentialsStore) (clientID string, scopes []string, err error) {
	slog.Debug("keep: resolving OAuth client credentials", "backend", serverName, "dcr_enabled", oauthCfg.DCR.Enabled)

	reg, err := cs.GetClientReg(ctx, serverName)
	if err != nil {
		return "", nil, fmt.Errorf("get client reg: %w", err)
	}

	if reg != nil {
		debugLogClientReg("keep: found existing dynamic client registration", reg, "backend", serverName)
	} else {
		slog.Debug("keep: no dynamic client registration found", "backend", serverName)
	}

	// Treat an expired dynamic secret the same as no registration.
	if reg != nil && reg.ClientSecretExpiresAt > 0 {
		expiresAt := time.Unix(reg.ClientSecretExpiresAt, 0)
		refreshBefore := expiresAt.Add(-oauthCfg.RefreshWindow())
		if time.Now().After(refreshBefore) {
			slog.Info("keep: dynamic client secret expired or within refresh window; re-registering",
				"backend", serverName, "expires_at", expiresAt)
			reg = nil
		}
	}

	if reg != nil {
		// Dynamic client exists — intersect effective scopes with IdP-granted scopes.
		effectiveScopes := oauthCfg.EffectiveScopes()
		if reg.Scopes != "" {
			effectiveScopes = intersectScopes(effectiveScopes, reg.Scopes)
		}
		slog.Debug("keep: using dynamic client credentials", "backend", serverName,
			"client_id", reg.ClientID, "effective_scopes", effectiveScopes)
		return reg.ClientID, effectiveScopes, nil
	}

	// Static client path.
	if !oauthCfg.DCR.Enabled {
		effectiveScopes := oauthCfg.EffectiveScopes()
		slog.Debug("keep: using static client credentials", "backend", serverName,
			"client_id", oauthCfg.ClientID, "scopes", effectiveScopes)
		return oauthCfg.ClientID, effectiveScopes, nil
	}

	// DCR path — use singleflight to deduplicate concurrent registration attempts
	// on this instance. The work function also acquires a distributed lock so that
	// only one instance globally communicates with the IdP.
	v, regErr, _ := r.dcrGroup.Do(serverName, func() (any, error) {
		return r.performDCR(ctx, serverName, oauthCfg, eps, cs)
	})
	if regErr != nil {
		return "", nil, regErr
	}
	reg = v.(*clientReg)
	effectiveScopes := oauthCfg.EffectiveScopes()
	if reg.Scopes != "" {
		effectiveScopes = intersectScopes(effectiveScopes, reg.Scopes)
	}
	return reg.ClientID, effectiveScopes, nil
}

// performDCR is the inner function executed inside the singleflight group.
// It handles local re-checks, negative cache, distributed locking, and the
// actual RegisterDynamicClient HTTP call.
func (r *Router) performDCR(ctx context.Context, serverName string, oauthCfg BackendOAuth, eps oauthEndpoints, cs CredentialsStore) (*clientReg, error) {
	slog.Debug("keep: entering DCR singleflight", "backend", serverName)

	// Local re-check: another goroutine on this instance may have already registered.
	if reg, err := cs.GetClientReg(ctx, serverName); err == nil && reg != nil {
		slog.Debug("keep: DCR local re-check found existing registration (won by peer goroutine)", "backend", serverName, "client_id", reg.ClientID)
		return reg, nil
	}

	// Negative cache check: a recent failure is still fresh.
	if reason, err := cs.GetDCRFailure(ctx, serverName); err == nil && reason != "" {
		slog.Debug("keep: DCR negative cache hit — skipping registration", "backend", serverName, "cached_reason", reason)
		return nil, fmt.Errorf("dcr previously failed for backend %q: %s", serverName, reason)
	}
	slog.Debug("keep: DCR negative cache miss — proceeding to registration", "backend", serverName)

	// Acquire a distributed lock to protect single-use Initial Access Tokens.
	slog.Debug("keep: acquiring DCR distributed lock", "backend", serverName)
	unlock, err := cs.LockDCR(ctx, serverName)
	if err != nil {
		return nil, fmt.Errorf("acquire dcr lock for %q: %w", serverName, err)
	}
	defer unlock()
	slog.Debug("keep: DCR lock acquired", "backend", serverName)

	// Global re-check: the lock-winner from another instance may have already stored the result.
	if reg, err := cs.GetClientReg(ctx, serverName); err == nil && reg != nil {
		slog.Debug("keep: DCR global re-check found existing registration (won by peer instance)", "backend", serverName, "client_id", reg.ClientID)
		return reg, nil
	}

	// Set registration_endpoint from eps (populated by resolveOAuthEndpoints).
	oauthCfg.DCR.RegistrationEndpoint = eps.RegistrationEndpoint
	slog.Debug("keep: beginning DCR HTTP registration",
		"backend", serverName,
		"registration_endpoint", oauthCfg.DCR.RegistrationEndpoint,
		"client_name", oauthCfg.DCR.ClientName,
		"has_iat", oauthCfg.DCR.InitialAccessToken != "",
		"has_software_statement", oauthCfg.DCR.SoftwareStatement != "",
		"scopes", oauthCfg.EffectiveScopes(),
	)

	// Use a conservative HTTP client for DCR; private address access is not needed
	// since registration endpoints must be reachable from the public internet.
	httpClient := newHTTPClient(false)
	reg, dcrErr := RegisterDynamicClient(ctx, httpClient, &oauthCfg)
	if dcrErr != nil {
		// Choose TTL based on error type.
		cacheTTL := oauthCfg.DCR.FailureCacheTTL
		if cacheTTL <= 0 {
			cacheTTL = 5 * time.Minute
		}
		if errors.Is(dcrErr, ErrDCRNotSupported) {
			cacheTTL = dcrProtocolMismatchTTL
			slog.Error("keep: DCR is enabled but IdP does not support RFC 7591; register the client manually and provide a static client_id",
				"backend", serverName)
		}
		slog.Debug("keep: DCR registration failed; caching failure", "backend", serverName, "error", dcrErr, "cache_ttl", cacheTTL)
		_ = cs.SetDCRFailure(ctx, serverName, dcrErr.Error(), cacheTTL)
		return nil, fmt.Errorf("dynamic client registration for %q: %w", serverName, dcrErr)
	}

	slog.Debug("keep: DCR registration HTTP call succeeded", "backend", serverName, "client_id", reg.ClientID,
		"token_endpoint_auth_method", reg.TokenEndpointAuthMethod, "scopes", reg.Scopes,
		"secret_expires_at", reg.ClientSecretExpiresAt)

	// Atomically persist the registration; another instance may have won the race
	// despite the lock (e.g. lock timeout / split-brain).
	set, err := cs.SetClientRegNX(ctx, serverName, reg)
	if err != nil {
		return nil, fmt.Errorf("persist client reg for %q: %w", serverName, err)
	}
	if !set {
		// Another instance stored a registration first — use theirs.
		winner, getErr := cs.GetClientReg(ctx, serverName)
		if getErr != nil || winner == nil {
			slog.Warn("keep: DCR race: could not retrieve winner's registration; using local result", "backend", serverName)
			return reg, nil
		}
		slog.Debug("keep: DCR race: using winner's registration from peer instance", "backend", serverName, "client_id", winner.ClientID)
		return winner, nil
	}

	slog.Info("keep: dynamic client registration succeeded", "backend", serverName, "client_id", reg.ClientID)
	return reg, nil
}

// intersectScopes returns the subset of want that is present in grantedSpace
// (a space-separated scope string as returned by the IdP).
func intersectScopes(want []string, grantedSpace string) []string {
	granted := make(map[string]struct{})
	for _, s := range strings.Fields(grantedSpace) {
		granted[s] = struct{}{}
	}
	var result []string
	for _, s := range want {
		if _, ok := granted[s]; ok {
			result = append(result, s)
		}
	}
	if len(result) == 0 {
		return want // fall back to configured scopes if intersection is empty
	}
	return result
}

// generatePKCEVerifier creates a high-entropy code verifier for PKCE (RFC 7636).
// The verifier is 32 random bytes encoded as base64url without padding.
func generatePKCEVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceChallenge computes the S256 code challenge for a given code verifier.
func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// generateNonce generates a 16-byte random state/nonce parameter.
func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// buildAuthURL constructs the authorization endpoint URL with PKCE and state parameters.
// resource is the RFC 8707 resource indicator; pass "" to omit it.
func buildAuthURL(authEndpoint, clientID, redirectURI string, scopes []string, state, codeChallenge, resource string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	if len(scopes) > 0 {
		params.Set("scope", strings.Join(scopes, " "))
	}
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	if resource != "" {
		params.Set("resource", resource) // RFC 8707
	}
	return authEndpoint + "?" + params.Encode()
}

// identityPathFor returns the IdentityPath configured for the named backend, or
// "" if the backend does not exist or has no path configured.
func (r *Router) identityPathFor(serverName string) string {
	r.mu.Lock()
	conn, ok := r.backends[serverName]
	r.mu.Unlock()
	if !ok {
		return ""
	}
	conn.cfgMu.RLock()
	path := conn.cfg.UserIdentity.Placement.JSONPath
	conn.cfgMu.RUnlock()
	return path
}

// applyIdentityExchange passes the raw token through the backend's IdentityExchanger
// and returns a context carrying the ExchangedIdentity to inject. Every backend
// has an exchanger: noopIdentityExchanger (wraps raw token) or IdentityExchangeClient.
// If the exchanger returns false, a nil ExchangedIdentity is stored so that neither
// header nor path injection occurs — the original token is never forwarded as a fallback.
func (r *Router) applyIdentityExchange(ctx context.Context, serverName string) context.Context {
	rawToken := rawTokenFromContext(ctx)
	if rawToken == "" {
		return ctx
	}

	r.exchangeMu.RLock()
	exchanger, ok := r.exchangers[serverName]
	r.exchangeMu.RUnlock()
	if !ok {
		// Exchanger not yet seeded (should not occur after the first Reload).
		return ctx
	}

	identity, ok := exchanger.Exchange(ctx, rawToken)
	if !ok {
		return withExchangedIdentity(ctx, nil) // fail-degraded: omit injection
	}
	return withExchangedIdentity(ctx, identity)
}

// resolveToolName returns the real backend tool name for the given alias, or
// the original name unchanged if no alias mapping exists for it.
func (r *Router) resolveToolName(serverName, toolName string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if conn, ok := r.backends[serverName]; ok && conn.aliasToReal != nil {
		if real, ok := conn.aliasToReal[toolName]; ok {
			return real
		}
	}
	return toolName
}

// ListTools returns all tools exposed by the named backend server.
func (r *Router) ListTools(ctx context.Context, serverName string) ([]*mcp.Tool, error) {
	r.mu.Lock()
	conn, ok := r.backends[serverName]
	r.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("unknown backend %q", serverName)
	}

	conn.cfgMu.RLock()
	source := conn.cfg.ToolList.Source
	staticTools := conn.cfg.StaticTools
	conn.cfgMu.RUnlock()

	if source == "file" {
		return staticTools, nil
	}

	session, err := r.sessionFor(ctx, serverName)
	if err != nil {
		return nil, err
	}
	resp, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		return nil, fmt.Errorf("list tools from %q: %w", serverName, err)
	}
	return resp.Tools, nil
}

// ListAllTools returns the cached aggregated tool list from all registered backends.
// The cache is populated at startup and refreshed via Reload.
func (r *Router) ListAllTools(ctx context.Context) ([]shared.AnnotatedTool, error) {
	r.cacheMu.RLock()
	defer r.cacheMu.RUnlock()
	return r.toolCache, nil
}

// Reload reconciles the backend map against the new config, re-surveys all
// backends via MCP ListTools, and updates the tool cache. Backends removed from
// config have their sessions closed. New backends are registered. Existing
// sessions are reused (connection params changes require restart — known gap).
// ToolMap changes take effect immediately on reload. A backend that fails to
// list tools is logged and skipped so one broken backend does not prevent the
// rest from being served. Duplicate aliases across backends are a hard error.
func (r *Router) Reload(ctx context.Context, backends []BackendConfig) error {
	// Load static tool files before acquiring the lock. File I/O must not
	// happen while holding the router mutex.
	for i := range backends {
		if backends[i].ToolList.Source == "file" {
			if err := loadStaticToolList(&backends[i]); err != nil {
				return fmt.Errorf("backend %q: %w", backends[i].Name, err)
			}
		}
	}

	r.mu.Lock()

	newBackends := make(map[string]BackendConfig, len(backends))
	for _, b := range backends {
		newBackends[b.Name] = b
	}

	// Close and remove backends no longer in config.
	for name, conn := range r.backends {
		if _, exists := newBackends[name]; !exists {
			if conn.session != nil {
				conn.session.Close()
			}
			delete(r.backends, name)
		}
	}

	// Register new backends and update configs for existing ones (so ToolMap,
	// ForwardHeaders, DropHeaders, and other non-connection settings take effect
	// without a restart). cfg writes are protected by the per-conn cfgMu so
	// concurrent RoundTrip calls always see a consistent snapshot.
	for name, cfg := range newBackends {
		if conn, exists := r.backends[name]; exists {
			conn.cfgMu.Lock()
			conn.cfg = cfg
			conn.cfgMu.Unlock()
		} else {
			r.backends[name] = &backendConn{cfg: cfg}
		}
	}

	// Validate alias uniqueness across all backends, then build aliasToReal
	// maps. aliasToReal is the inverse of ToolMap (alias → real backend name).
	seenAliases := make(map[string]string) // alias → backend that claimed it
	for name, conn := range r.backends {
		for realName, alias := range conn.cfg.ToolMap {
			if claimedBy, dup := seenAliases[alias]; dup {
				r.mu.Unlock()
				return fmt.Errorf("tool alias %q is claimed by both backend %q and %q — aliases must be unique across all backends (real names: %q)", alias, claimedBy, name, realName)
			}
			seenAliases[alias] = name
		}
	}
	for _, conn := range r.backends {
		if len(conn.cfg.ToolMap) == 0 {
			conn.aliasToReal = nil
		} else {
			m := make(map[string]string, len(conn.cfg.ToolMap))
			for realName, alias := range conn.cfg.ToolMap {
				m[alias] = realName
			}
			conn.aliasToReal = m
		}
	}

	// Snapshot names and configs before releasing the lock so the survey and
	// exchange-client build loops below do not need to re-acquire mu.
	type backendSnapshot struct {
		toolMap map[string]string
		cfg     BackendConfig
	}
	snapshots := make(map[string]backendSnapshot, len(r.backends))
	names := make([]string, 0, len(r.backends))
	for name, conn := range r.backends {
		snapshots[name] = backendSnapshot{toolMap: conn.cfg.ToolMap, cfg: conn.cfg}
		names = append(names, name)
	}
	r.mu.Unlock()

	// Build an IdentityExchanger for every backend. Done outside mu since it may
	// involve DNS lookups or Redis Ping calls.
	// Every backend gets exactly one exchanger: noopIdentityExchanger for backends
	// without an exchange URL, IdentityExchangeClient for those that have one, or
	// failDegradedExchanger if client construction fails.
	newExchangers := make(map[string]IdentityExchanger, len(names))
	for _, name := range names {
		snap := snapshots[name]
		if snap.cfg.UserIdentity.Exchange.URL == "" {
			newExchangers[name] = noopIdentityExchanger{}
			continue
		}
		client, err := newIdentityExchangeClient(ctx, snap.cfg, r.storageConfig)
		if err != nil {
			return fmt.Errorf("backend %q: identity exchange client unavailable: %w", name, err)
		}
		newExchangers[name] = client
	}
	r.exchangeMu.Lock()
	r.exchangers = newExchangers
	r.exchangeMu.Unlock()

	// Survey all backends (without holding mu to avoid deadlock with sessionFor).
	var surveys []backendSurvey
	for _, name := range names {
		tools, err := r.ListTools(ctx, name)
		if err != nil {
			slog.Warn("reload: list tools failed for backend", "backend", name, "error", err)
			continue
		}
		surveys = append(surveys, backendSurvey{name: name, toolMap: snapshots[name].toolMap, tools: tools})
	}

	all, err := buildToolCache(surveys)
	if err != nil {
		return err
	}

	r.cacheMu.Lock()
	r.toolCache = all
	r.cacheMu.Unlock()

	slog.Info("tool cache refreshed", "tool_count", len(all), "backend_count", len(names))
	return nil
}

// backendSurvey holds the result of a single backend's ListTools call together
// with its alias map, ready to be merged into the global tool cache.
type backendSurvey struct {
	name    string
	toolMap map[string]string // real name → alias (from BackendConfig.ToolMap)
	tools   []*mcp.Tool
}

// buildToolCache merges surveyed tools from all backends into a single list,
// applying any alias mappings and returning an error if any effective name
// (alias or real) appears more than once across all backends.
// This catches alias-vs-alias, alias-vs-unaliased, and unaliased-vs-unaliased
// collisions that would otherwise silently shadow tools in the agent's view.
func buildToolCache(surveys []backendSurvey) ([]shared.AnnotatedTool, error) {
	type effectiveEntry struct {
		backendName string
		realName    string // non-empty only when the effective name is an alias
	}
	seenEffective := make(map[string]effectiveEntry)
	var all []shared.AnnotatedTool

	for _, s := range surveys {
		for _, t := range s.tools {
			effectiveName := t.Name
			var realName string
			if alias, ok := s.toolMap[t.Name]; ok {
				realName = t.Name
				effectiveName = alias
			}
			if prior, dup := seenEffective[effectiveName]; dup {
				return nil, fmt.Errorf(
					"effective tool name %q collides: %s and %s — use tool_map to give one a unique alias",
					effectiveName,
					describeToolEntry(prior.backendName, effectiveName, prior.realName),
					describeToolEntry(s.name, effectiveName, realName),
				)
			}
			seenEffective[effectiveName] = effectiveEntry{backendName: s.name, realName: realName}

			entry := shared.AnnotatedTool{ServerName: s.name, Tool: t}
			if realName != "" {
				// Shallow-copy the tool so we do not mutate the SDK-owned value.
				toolCopy := *t
				toolCopy.Name = effectiveName
				entry.Tool = &toolCopy
			}
			all = append(all, entry)
		}
	}
	return all, nil
}

// describeToolEntry returns a human-readable description of how a backend
// exposes a tool, for use in collision error messages.
func describeToolEntry(backendName, effectiveName, realName string) string {
	if realName != "" {
		return fmt.Sprintf("backend %q exposes it as an alias for %q", backendName, realName)
	}
	return fmt.Sprintf("backend %q exposes %q as its real name", backendName, effectiveName)
}

// isDeadSessionError reports whether err indicates a stale or closed MCP
// client session that should be dropped and re-established.
func isDeadSessionError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "connection closed") ||
		strings.Contains(s, "client is closing") ||
		strings.Contains(s, "exceeded 5 retries")
}

// dropSession removes the cached MCP session for the named backend so that the
// next call to sessionFor will establish a fresh connection.
// The old session is closed asynchronously (best-effort) since it may already
// be in a broken state.
func (r *Router) dropSession(serverName string) {
	r.mu.Lock()
	conn, ok := r.backends[serverName]
	if !ok {
		r.mu.Unlock()
		return
	}
	oldSession := conn.session
	conn.session = nil
	conn.client = nil
	r.mu.Unlock()
	if oldSession != nil {
		go func() { _ = oldSession.Close() }()
	}
	slog.Info("keep: dropped stale MCP session", "backend", serverName)
}

// sessionFor returns an active MCP client session for the named backend,
// establishing the connection if it does not yet exist.
func (r *Router) sessionFor(ctx context.Context, serverName string) (*mcp.ClientSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	conn, ok := r.backends[serverName]
	if !ok {
		return nil, fmt.Errorf("unknown backend %q", serverName)
	}
	if conn.session != nil {
		slog.Debug("keep: reusing existing MCP session", "backend", serverName)
		return conn.session, nil
	}

	slog.Debug("keep: establishing new MCP session", "backend", serverName, "type", conn.cfg.Type, "url", conn.cfg.URL)

	transport, err := buildBackendTransport(conn)
	if err != nil {
		return nil, fmt.Errorf("build transport for %q: %w", serverName, err)
	}

	conn.client = mcp.NewClient(&mcp.Implementation{
		Name:    shared.ServiceKeep,
		Version: version.Version,
	}, nil)

	slog.Debug("keep: sending MCP initialize to backend", "backend", serverName)
	session, err := conn.client.Connect(ctx, transport, nil)
	if err != nil {
		slog.Debug("keep: MCP initialize failed", "backend", serverName, "error", err)
		return nil, fmt.Errorf("connect to backend %q: %w", serverName, err)
	}
	slog.Debug("keep: MCP session established", "backend", serverName)
	conn.session = session
	return session, nil
}

// buildBackendTransport creates the appropriate MCP transport for a backend.
// For HTTP and SSE backends the HTTP client is wrapped with a
// headerInjectingRoundTripper that forwards client headers from the request
// context according to the live ForwardHeaders/DropHeaders config on conn.
// Called from sessionFor which holds r.mu, so reading conn.cfg directly is safe.
func buildBackendTransport(conn *backendConn) (mcp.Transport, error) {
	cfg := conn.cfg
	switch cfg.Type {
	case "stdio":
		if cfg.Command == "" {
			return nil, fmt.Errorf("stdio backend requires a command")
		}
		cmd := exec.Command(cfg.Command, cfg.Args...)
		if len(cfg.Env) > 0 {
			// Start from the parent environment so PATH and other essentials
			// are inherited, then overlay the per-backend overrides.
			cmd.Env = os.Environ()
			for k, v := range cfg.Env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
		}
		return &mcp.CommandTransport{Command: cmd}, nil
	case "http":
		if cfg.URL == "" {
			return nil, fmt.Errorf("http backend requires a URL")
		}
		if err := checkBackendURL(cfg.URL, cfg.AllowPrivateAddresses); err != nil {
			return nil, fmt.Errorf("http backend URL rejected: %w", err)
		}
		httpClient := newHTTPClient(false)
		httpClient.Transport = &headerInjectingRoundTripper{conn: conn, inner: http.DefaultTransport}
		return &mcp.StreamableClientTransport{
			Endpoint:   cfg.URL,
			HTTPClient: httpClient,
		}, nil
	case "sse":
		if cfg.URL == "" {
			return nil, fmt.Errorf("sse backend requires a URL")
		}
		if err := checkBackendURL(cfg.URL, cfg.AllowPrivateAddresses); err != nil {
			return nil, fmt.Errorf("sse backend URL rejected: %w", err)
		}
		httpClient := newHTTPClient(false)
		httpClient.Transport = &headerInjectingRoundTripper{conn: conn, inner: http.DefaultTransport}
		return &mcp.SSEClientTransport{
			Endpoint:   cfg.URL,
			HTTPClient: httpClient,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported backend type %q (valid types: stdio, http, sse)", cfg.Type)
	}
}

// headerInjectingRoundTripper is a stateful http.RoundTripper that injects
// client headers from the request context into every outgoing backend request.
//
// It reads ForwardHeaders and DropHeaders from conn.cfg at call time (protected
// by conn.cfgMu) so that config changes applied by Router.Reload take effect
// immediately without requiring a backend reconnection.
//
// Header selection follows strict precedence:
//  1. Forbidden (hard-coded) — always stripped, regardless of configuration.
//  2. DropHeaders (config deny) — stripped next if matched.
//  3. ForwardHeaders (config allow) — forwarded if matched; default is ["*"].
type headerInjectingRoundTripper struct {
	conn  *backendConn
	inner http.RoundTripper
}

// RoundTrip injects allowed client headers into the outgoing request and
// delegates to the inner transport. The original request is never mutated.
// If IdentityHeader is configured and the exchanged identity is a plain string,
// it is injected as that header, overwriting any forwarded client header of the
// same name. JSON object/array identities are never used as header values; a
// warning is logged and header injection is skipped for those.
func (t *headerInjectingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clientHeaders := clientHeadersFromContext(req.Context())
	identity := exchangedIdentityFromContext(req.Context())

	t.conn.cfgMu.RLock()
	fwdHeaders := t.conn.cfg.ForwardHeaders
	dropHeaders := t.conn.cfg.DropHeaders
	identityHeader := t.conn.cfg.UserIdentity.Placement.Header
	identityType := t.conn.cfg.UserIdentity.Type
	apiKeyValue := t.conn.cfg.UserIdentity.APIKey.Source
	t.conn.cfgMu.RUnlock()

	oauthToken := oauthTokenFromContext(req.Context())

	debugLogRequest("keep: backend→ request", req)
	if oauthToken != "" {
		debugLogBearerToken("keep: backend→ outgoing Bearer token", oauthToken, "backend", t.conn.cfg.Name)
	}

	var resp *http.Response
	var err error

	needsInjection := len(clientHeaders) > 0 ||
		((identityType == "" || identityType == "exchange") && identityHeader != "" && identity != nil) ||
		(identityType == "api_key" && identityHeader != "" && apiKeyValue != "") ||
		(identityType == "oauth" && oauthToken != "")

	if !needsInjection {
		// Nothing to inject; skip cloning.
		resp, err = t.inner.RoundTrip(req)
	} else {
		if len(fwdHeaders) == 0 {
			fwdHeaders = []string{"*"}
		}

		outReq := req.Clone(req.Context())
		for name, vals := range clientHeaders {
			// Step 1: skip forbidden headers (should already be excluded by Gate,
			// but enforce again as defence-in-depth).
			if shared.IsForbiddenHeader(name) {
				continue
			}
			// Step 2: skip headers matched by the drop list.
			dropped := false
			for _, pattern := range dropHeaders {
				if shared.MatchesHeaderPattern(pattern, name) {
					dropped = true
					break
				}
			}
			if dropped {
				continue
			}
			// Step 3: forward headers matched by the forward list.
			for _, pattern := range fwdHeaders {
				if shared.MatchesHeaderPattern(pattern, name) {
					outReq.Header[name] = vals
					break
				}
			}
		}

		// Inject identity header last so it overrides any forwarded client header
		// of the same name. JSON object/array identities cannot be header values —
		// skip with a warning so the request still proceeds (non-fatal).
		switch identityType {
		case "api_key":
			if identityHeader != "" && apiKeyValue != "" {
				outReq.Header.Set(identityHeader, apiKeyValue)
				slog.Info("keep: injected api_key into request header", "backend", t.conn.cfg.Name, "header", identityHeader)
			}
		case "oauth":
			if oauthToken != "" {
				// Use the configured placement header if set; otherwise default to
				// the standard Authorization header so zero-config backends work.
				oauthHeader := identityHeader
				if oauthHeader == "" {
					oauthHeader = "Authorization"
				}
				outReq.Header.Set(oauthHeader, "Bearer "+oauthToken)
				slog.Info("keep: injected OAuth token into request header", "backend", t.conn.cfg.Name, "header", oauthHeader)
			}
		case "none":
			// Explicit no-op: type "none" means no identity injection of any kind.
		default:
			// "" or "exchange" — use the exchanged identity (existing behaviour).
			if identityHeader != "" {
				if identity == nil {
					slog.Warn("keep: identity injection configured but no identity token in context — skipping header injection", "backend", t.conn.cfg.Name, "header", identityHeader)
				} else if identity.Structured != nil {
					slog.Warn("keep: identity exchange returned a JSON object/array; cannot inject as HTTP header, skipping header injection",
						"backend", t.conn.cfg.Name, "header", identityHeader)
				} else {
					outReq.Header.Set(identityHeader, identity.Str)
					slog.Info("keep: injected identity into request header", "backend", t.conn.cfg.Name, "header", identityHeader)
				}
			}
		}

		debugLogHeaders("keep: backend→ outgoing headers (post-injection)", outReq.Header, "backend", t.conn.cfg.Name)
		resp, err = t.inner.RoundTrip(outReq)
	}

	if resp != nil {
		debugLogResponse("keep: backend← response", resp, "backend", t.conn.cfg.Name)
		if wwwAuth := resp.Header.Get("WWW-Authenticate"); wwwAuth != "" {
			slog.Debug("keep: backend← WWW-Authenticate header present", "backend", t.conn.cfg.Name, "www_authenticate", wwwAuth)
		}
		// Log error response bodies at debug level so we can see IdP error messages.
		if resp.StatusCode >= 400 {
			debugLogResponseBody("keep: backend← error response body", resp, 4096)
		}
	}
	if err != nil {
		slog.Debug("keep: backend← transport error", "backend", t.conn.cfg.Name, "error", err)
	}

	// Capture the HTTP status and response headers from the first non-2xx
	// response so that CallTool can surface them to the agent.
	if resp != nil && resp.StatusCode >= 400 {
		if cap := backendRespCaptureFromContext(req.Context()); cap != nil {
			cap.mu.Lock()
			if cap.statusCode == 0 {
				cap.statusCode = resp.StatusCode
				cap.headers = resp.Header.Clone()
			}
			cap.mu.Unlock()
		}
	}

	return resp, err
}

// newHTTPClient returns an *http.Client that always refuses redirects.
//
// When blockPrivate is true the transport additionally rejects connections to
// private, loopback, and link-local addresses at dial time (checked against
// privateRanges after DNS resolution).  Use this for any request whose URL
// originates from an untrusted external source — for example, URLs extracted
// from a backend's WWW-Authenticate header during OAuth discovery.
//
// When blockPrivate is false the client uses http.DefaultTransport, which is
// appropriate when the URL has already been validated at config load time via
// checkBackendURL.
func newHTTPClient(blockPrivate bool) *http.Client {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("redirects are not permitted (attempted redirect to %s)", req.URL)
		},
	}
	if !blockPrivate {
		return client
	}
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	client.Transport = &http.Transport{
		ForceAttemptHTTP2: true,
		MaxIdleConns:      10,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("malformed address %q: %w", addr, err)
			}
			ips, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("DNS lookup for %q: %w", host, err)
			}
			for _, ipStr := range ips {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					continue
				}
				for _, private := range privateRanges {
					if private.Contains(ip) {
						return nil, fmt.Errorf(
							"host %q resolves to private/loopback address %s",
							host, ipStr)
					}
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
		},
	}
	return client
}

// privateRanges lists the CIDR blocks that must not be reachable via HTTP
// backend URLs: RFC 1918 private ranges, loopback, and link-local.
//
// this is specifically for SSRF protection. It can be disabled by setting
// the config variable:
//
//	backends.<backend>.allow_private_addresses: true
var privateRanges = func() []*net.IPNet {
	var ranges []*net.IPNet
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"169.254.0.0/16", // IPv4 link-local
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique-local
	} {
		_, network, _ := net.ParseCIDR(cidr)
		ranges = append(ranges, network)
	}
	return ranges
}()

// backendRespCapture holds the HTTP status code and response headers from the
// first non-2xx response received during a single CallTool dispatch. A pointer
// to this struct is stored in the context before the call so that
// headerInjectingRoundTripper can fill it without needing a separate channel or
// return value. Only the first non-2xx response is captured.
type backendRespCapture struct {
	mu         sync.Mutex
	statusCode int
	headers    http.Header
}

type backendRespKey struct{}

func withBackendRespCapture(ctx context.Context) (context.Context, *backendRespCapture) {
	cap := &backendRespCapture{}
	return context.WithValue(ctx, backendRespKey{}, cap), cap
}

func backendRespCaptureFromContext(ctx context.Context) *backendRespCapture {
	v, _ := ctx.Value(backendRespKey{}).(*backendRespCapture)
	return v
}

// injectAtPath sets value at the dot-separated path within m, creating
// intermediate maps as needed. If a non-map value already exists at an
// intermediate segment, it is replaced with a new map so injection can proceed.
// The last segment is always set to value, overwriting any existing entry.
//
// Every intermediate map is always freshly allocated, even when an existing
// map[string]any already occupies that segment. This guarantees that m and its
// descendants are never shared with the caller's original map, so writes at any
// depth cannot leak back through a shared pointer.
func injectAtPath(m map[string]any, path string, value any) {
	segments := strings.Split(path, ".")
	cur := m
	for i, seg := range segments {
		if i == len(segments)-1 {
			cur[seg] = value
			return
		}
		// Copy the existing intermediate map (if any) so we never mutate a
		// map that is also reachable from the caller's original args.
		existing, _ := cur[seg].(map[string]any)
		next := make(map[string]any, len(existing))
		for k, v := range existing {
			next[k] = v
		}
		cur[seg] = next
		cur = next
	}
}

// checkBackendURL validates that a backend URL is an absolute HTTP/HTTPS URL.
// Unless allowPrivate is true, it also rejects hosts that resolve to RFC 1918,
// loopback, or link-local addresses. This is a config-load-time check; the
// no-redirect client handles runtime SSRF regardless of this setting.
func checkBackendURL(rawURL string, allowPrivate bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q not allowed; use http or https", u.Scheme)
	}
	if allowPrivate {
		return nil
	}
	hostname := u.Hostname()
	ips, err := net.LookupHost(hostname)
	if err != nil {
		// DNS failure at config time is non-fatal: the host may not be
		// resolvable in the build/test environment. Log and allow.
		slog.Warn("backend URL: could not resolve host at config time",
			"host", hostname, "error", err)
		return nil
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		for _, private := range privateRanges {
			if private.Contains(ip) {
				return fmt.Errorf("host %q resolves to private/loopback address %s — "+
					"set allow_private_addresses: true if this backend is intentionally on an internal network",
					hostname, ipStr)
			}
		}
	}
	return nil
}
