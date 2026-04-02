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
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	"github.com/paclabsnet/PortcullisMCP/internal/shared/tlsutil"
)

// escalationRequestClaims are the JWT claims Keep embeds in approval URL tokens.
// These must match the claims Keep writes in internal/keep/escalation.go.
type escalationRequestClaims struct {
	jwt.RegisteredClaims
	UserID          string           `json:"uid"`
	UserDisplayName string           `json:"uname,omitempty"`
	Server          string           `json:"srv"`
	Tool            string           `json:"tool"`
	Reason          string           `json:"reason"`
	EscalationScope []map[string]any `json:"scope,omitempty"`
}

// portcullisClaims is the nested object stored under the "portcullis" JWT claim.
// scope carries the PDP-issued escalation scope constraints.
// tools and services record exactly what was approved so the PDP can enforce
// that the token is only used for the escalated operation.
// reason is a human-readable audit trail of who approved the escalation.
type portcullisClaims struct {
	Reason          string           `json:"reason,omitempty"`
	ArgRestrictions []map[string]any `json:"arg_restrictions,omitempty"`
	Tools           []string         `json:"tools,omitempty"`
	Services        []string         `json:"services,omitempty"`
}

// escalationTokenClaims are the JWT claims Guard issues after user approval.
type escalationTokenClaims struct {
	jwt.RegisteredClaims
	Portcullis portcullisClaims `json:"portcullis,omitempty"`
}

// Server is the portcullis-guard HTTP server.
type Server struct {
	cfg        Config
	keepKey    []byte
	signingKey []byte
	ttl        time.Duration
	templates  *template.Template

	// pending holds Keep-signed escalation request JWTs registered by Gate
	// before it presents the approval URL.  Keyed by JTI.
	pending PendingStore

	// unclaimed holds approved escalation tokens not yet collected by Gate.
	unclaimed UnclaimedStore

	// uiReady and apiReady are set to true once each listener is successfully bound.
	// handleReadyz returns 503 until both are true.
	uiReady  atomic.Bool
	apiReady atomic.Bool
}

// NewServer creates a Guard server from config.
// cfg must already have secrets resolved (use LoadConfig, which calls the
// shared config loader, for file-based startup).
func NewServer(ctx context.Context, cfg Config) (*Server, error) {
	cfg.Limits.ApplyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Emit a startup warning when token APIs are explicitly left open for development.
	if cfg.Auth.BearerToken == "" && cfg.Auth.Mtls.ClientCA == "" && cfg.Auth.AllowUnauthenticated {
		slog.Warn("Guard token APIs are running without authentication — do not use in production",
			"affected_endpoints", []string{"/token/unclaimed/list", "/token/deposit", "/pending", "/token/claim"})
	}

	ttl := time.Duration(cfg.EscalationTokenSigning.TTL) * time.Second
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	tmpl, err := loadTemplates(cfg.Templates.Dir)
	if err != nil {
		return nil, fmt.Errorf("load templates: %w", err)
	}

	pending, unclaimed, err := buildStores(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("init token stores: %w", err)
	}

	return &Server{
		cfg:        cfg,
		keepKey:    []byte(cfg.Keep.PendingEscalationRequestSigningKey),
		signingKey: []byte(cfg.EscalationTokenSigning.Key),
		ttl:        ttl,
		templates:  tmpl,
		pending:    pending,
		unclaimed:  unclaimed,
	}, nil
}

// buildStores constructs the PendingStore and UnclaimedStore selected by cfg.
// Returns in-memory stores for "memory" (or empty) backend, Redis stores for
// "redis" backend.
func buildStores(ctx context.Context, cfg Config) (PendingStore, UnclaimedStore, error) {
	switch cfg.TokenStore.Backend {
	case "", "memory":
		return NewMemPendingStore(cfg.Limits.MaxPendingRequests),
			NewMemUnclaimedStore(cfg.Limits.MaxUnclaimedPerUser, cfg.Limits.MaxUnclaimedTotal),
			nil
	case "redis":
		client, err := NewRedisClient(ctx, cfg.TokenStore.Redis)
		slog.Debug("Creating new redis client for token storage: ", "config", cfg.TokenStore.Redis)
		if err != nil {
			return nil, nil, err
		}
		prefix := cfg.TokenStore.Redis.KeyPrefix
		return NewRedisPendingStore(client, prefix),
			NewRedisUnclaimedStore(client, prefix, cfg.Limits.MaxUnclaimedPerUser),
			nil
	default:
		// Validate() should have caught this, but be defensive.
		return nil, nil, fmt.Errorf("unknown token_store.backend %q", cfg.TokenStore.Backend)
	}
}

// loadTemplates loads approval.html and token.html from dir.
func loadTemplates(dir string) (*template.Template, error) {
	if dir == "" {
		return nil, fmt.Errorf("templates.dir is required")
	}
	pattern := filepath.Join(dir, "*.html")
	tmpl, err := template.ParseGlob(pattern)
	if err != nil {
		return nil, fmt.Errorf("parse templates from %q: %w", dir, err)
	}
	for _, name := range []string{"approval.html", "token.html"} {
		if tmpl.Lookup(name) == nil {
			return nil, fmt.Errorf("required template %q not found in %q", name, dir)
		}
	}
	return tmpl, nil
}

// Run starts the UI and API listeners and blocks until ctx is cancelled.
// The UI listener serves the human-facing approval page (/approve).
// The API listener serves all machine-to-machine endpoints (/token/*, /pending)
// and enforces machine authentication via machineAuth middleware.
func (s *Server) Run(ctx context.Context) error {
	// UI mux: human-facing routes only.
	uiMux := http.NewServeMux()
	uiMux.HandleFunc("GET /healthz", s.handleHealthz)
	uiMux.HandleFunc("GET /readyz", s.handleReadyz)
	uiMux.HandleFunc("GET /approve", s.handleGet)
	uiMux.HandleFunc("POST /approve", s.handlePost)

	// API mux: machine-to-machine routes, all behind machineAuth.
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("GET /healthz", s.handleHealthz)
	apiMux.HandleFunc("GET /readyz", s.handleReadyz)
	apiMux.HandleFunc("GET /token/unclaimed/list", s.machineAuth(s.handleTokenUnclaimedList))
	apiMux.HandleFunc("POST /token/deposit", s.machineAuth(s.handleTokenDeposit))
	apiMux.HandleFunc("POST /token/claim", s.machineAuth(s.handleTokenClaim))
	apiMux.HandleFunc("POST /pending", s.machineAuth(s.handlePending))

	go s.cleanupWorker(ctx)

	uiSrv := &http.Server{Handler: uiMux}
	apiSrv := &http.Server{Handler: apiMux}

	// Build TLS configs from the listen config and auth.mtls settings.
	if s.cfg.Listen.UITLS.Cert != "" {
		tlsCfg, err := tlsutil.BuildServerTLS(s.cfg.Listen.UITLS)
		if err != nil {
			return fmt.Errorf("build UI TLS config: %w", err)
		}
		uiSrv.TLSConfig = tlsCfg
	}
	apiTLSCfg := s.cfg.Listen.APITLS
	if s.cfg.Auth.Mtls.ClientCA != "" {
		apiTLSCfg.ClientCA = s.cfg.Auth.Mtls.ClientCA
	}
	if apiTLSCfg.Cert != "" {
		tlsCfg, err := tlsutil.BuildServerTLSOptionalClient(apiTLSCfg)
		if err != nil {
			return fmt.Errorf("build API TLS config: %w", err)
		}
		apiSrv.TLSConfig = tlsCfg
	}

	// Bind both listeners before accepting any connections.
	uiLn, err := net.Listen("tcp", s.cfg.Listen.UIAddress)
	if err != nil {
		return fmt.Errorf("bind UI listener %s: %w", s.cfg.Listen.UIAddress, err)
	}
	apiLn, err := net.Listen("tcp", s.cfg.Listen.APIAddress)
	if err != nil {
		_ = uiLn.Close()
		return fmt.Errorf("bind API listener %s: %w", s.cfg.Listen.APIAddress, err)
	}

	// Wrap with TLS if configured.
	if uiSrv.TLSConfig != nil {
		uiLn = tls.NewListener(uiLn, uiSrv.TLSConfig)
	}
	if apiSrv.TLSConfig != nil {
		apiLn = tls.NewListener(apiLn, apiSrv.TLSConfig)
	}

	// Both listeners are bound — mark as ready for health probes.
	s.uiReady.Store(true)
	s.apiReady.Store(true)
	slog.Info("portcullis-guard UI listener ready", "addr", uiLn.Addr())
	slog.Info("portcullis-guard API listener ready", "addr", apiLn.Addr())

	// Cancel-driven shutdown: when ctx is done, both servers shut down gracefully.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-runCtx.Done()
		_ = uiSrv.Shutdown(context.Background())
		_ = apiSrv.Shutdown(context.Background())
	}()

	errCh := make(chan error, 2)
	go func() {
		defer cancel() // if this server exits unexpectedly, shut down the other
		if err := uiSrv.Serve(uiLn); !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("UI server: %w", err)
			return
		}
		errCh <- nil
	}()
	go func() {
		defer cancel()
		if err := apiSrv.Serve(apiLn); !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("API server: %w", err)
			return
		}
		errCh <- nil
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// machineAuth is middleware that enforces machine authentication on API endpoints.
// Auth is checked in order:
//  1. mTLS: if the TLS listener verified a client certificate, grant access.
//  2. Bearer: if a valid Authorization: Bearer token is provided, grant access.
//  3. Nag-ware: if allow_unauthenticated is true, log a warning and grant access.
//  4. Fail: return 401 Unauthorized.
func (s *Server) machineAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. mTLS: listener has verified peer certs via VerifyClientCertIfGiven.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			next(w, r)
			return
		}
		// 2. Bearer token.
		if s.cfg.Auth.BearerToken != "" {
			auth := r.Header.Get("Authorization")
			expected := "Bearer " + s.cfg.Auth.BearerToken
			if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) == 1 {
				next(w, r)
				return
			}
		}
		// 3. Dev / nag-ware mode.
		if s.cfg.Auth.AllowUnauthenticated {
			slog.Warn("guard: unauthenticated API access — do not use in production",
				"remote", r.RemoteAddr, "path", r.URL.Path)
			next(w, r)
			return
		}
		// 4. Fail closed.
		slog.Warn("guard: unauthorized API request", "remote", r.RemoteAddr, "path", r.URL.Path)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

// verifyRequest parses and verifies a Keep-signed escalation request JWT.
func (s *Server) verifyRequest(tokenStr string) (*escalationRequestClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &escalationRequestClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.keepKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	claims, ok := token.Claims.(*escalationRequestClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

// issueEscalationToken signs a new escalation token granting scope.
// scope is typically claims.EscalationScope but may be an edited version
// supplied by the approving user on the approval page.
//
// The issued token's JTI is set to requestJTI (the ID of the Keep-signed
// pending escalation request JWT). Gate tracks pending escalations by this JTI
// so it can correlate the approved token back to the original request.
// NOTE: the JTI is shared between the pending request JWT (issued by Keep) and
// the escalation token JWT (issued by Guard). This is intentional for correlation
// purposes and does not violate RFC 7519 — the tokens have different issuers.
func (s *Server) issueEscalationToken(claims *escalationRequestClaims, requestJTI string, scope []map[string]any) (string, time.Time, error) {
	now := time.Now()
	expiry := now.Add(s.ttl)

	// If the pending request JWT has no JTI (e.g. older Keep version), generate one.
	jti := requestJTI
	if jti == "" {
		jti = uuid.NewString()
	}

	actor := claims.UserDisplayName
	if actor == "" {
		actor = claims.UserID
	}
	reason := fmt.Sprintf("User %s has approved a temporary escalation of privileges for the Agent", actor)

	tokenClaims := escalationTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    shared.ServiceGuard,
			Subject:   claims.UserID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiry),
		},
		Portcullis: portcullisClaims{
			Reason:          reason,
			ArgRestrictions: scope,
			Tools:           []string{claims.Tool},
			Services:        []string{claims.Server},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims)
	signed, err := token.SignedString(s.signingKey)
	return signed, expiry, err
}

// handleGet renders the approval page for a Keep-signed escalation request.
// Accepts either ?token=<jwt> (user-driven mode: JWT embedded in URL) or
// ?jti=<uuid> (proactive mode: Gate pre-registered the JWT via POST /pending).
func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		// Proactive mode: look up the pre-registered JWT by JTI.
		jti := r.URL.Query().Get("jti")
		if jti == "" {
			http.Error(w, "missing token or jti", http.StatusBadRequest)
			return
		}
		pr, ok, err := s.pending.GetPending(r.Context(), jti)
		if err != nil {
			slog.Error("pending store lookup", "error", err, "jti", jti)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !ok {
			slog.Warn("approval page: pending request not found for jti", "jti", jti, "remote", r.RemoteAddr)
			http.Error(w, "escalation request not found or expired", http.StatusNotFound)
			return
		}
		tokenStr = pr.JWT
	}
	claims, err := s.verifyRequest(tokenStr)
	if err != nil {
		slog.Warn("invalid escalation request token", "error", err, "remote", r.RemoteAddr)
		http.Error(w, "invalid or expired approval link", http.StatusUnauthorized)
		return
	}

	scopeJSON, _ := json.MarshalIndent(claims.EscalationScope, "", "  ")
	data := approvalPageData{
		UserID:          claims.UserID,
		UserDisplayName: claims.UserDisplayName,
		Server:          claims.Server,
		Tool:            claims.Tool,
		Reason:          claims.Reason,
		ScopeJSON:       string(scopeJSON),
		Token:           tokenStr,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "approval.html", data); err != nil {
		slog.Error("render approval page", "error", err)
	}
}

// handlePost processes the user's approval and issues an escalation token.
func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Limits.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.Limits.MaxRequestBodyBytes))
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	tokenStr := r.FormValue("token")
	if tokenStr == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	claims, err := s.verifyRequest(tokenStr)
	if err != nil {
		slog.Warn("invalid escalation request token on approve", "error", err, "remote", r.RemoteAddr)
		http.Error(w, "invalid or expired approval link", http.StatusUnauthorized)
		return
	}

	scope := claims.EscalationScope
	if overrideStr := r.FormValue("scope_override"); overrideStr != "" {
		if err := shared.CheckLen(overrideStr, "scope_override", s.cfg.Limits.MaxScopeOverrideBytes); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var overrideScope []map[string]any
		if err := json.Unmarshal([]byte(overrideStr), &overrideScope); err != nil {
			http.Error(w, "invalid scope JSON in override", http.StatusBadRequest)
			return
		}
		scope = overrideScope
		slog.Info("approver modified escalation scope",
			"user_id", claims.UserID,
			"server", claims.Server,
			"tool", claims.Tool,
			"original_scope", claims.EscalationScope,
			"override_scope", overrideScope,
		)
	}

	escalationToken, expiry, err := s.issueEscalationToken(claims, claims.ID, scope)
	if err != nil {
		slog.Error("issue escalation token", "error", err)
		http.Error(w, "failed to generate escalation token", http.StatusInternalServerError)
		return
	}

	// Add the issued token to the unclaimed list so Gate can collect it
	// automatically without the user needing to paste it manually.
	if err := s.unclaimed.AddUnclaimed(r.Context(), UnclaimedToken{
		UserID:    claims.UserID,
		JTI:       claims.ID,
		Raw:       escalationToken,
		ExpiresAt: expiry,
	}); err != nil {
		// Non-fatal: the token is shown on screen so the user can paste it
		// manually, but Gate-side polling won't find it.
		slog.Warn("add unclaimed token after approval", "error", err, "jti", claims.ID)
	}

	scopeJSON, _ := json.Marshal(scope)
	slog.Info("escalation token issued",
		"user_id", claims.UserID,
		"user_display_name", claims.UserDisplayName,
		"server", claims.Server,
		"tool", claims.Tool,
		"reason", claims.Reason,
		"escalation_scope", string(scopeJSON),
		"jti", claims.ID,
		"issuer", shared.ServiceGuard,
		"expires_at", expiry.UTC().Format(time.RFC3339),
		"remote", r.RemoteAddr,
	)

	gatePort := s.cfg.PortcullisGateManagementPort
	var gateURL string
	if gatePort != 0 {
		gateURL = fmt.Sprintf("http://localhost:%d", gatePort)
	}

	data := tokenPageData{
		Server:          claims.Server,
		Tool:            claims.Tool,
		EscalationToken: escalationToken,
		GateURL:         gateURL,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "token.html", data); err != nil {
		slog.Error("render token page", "error", err)
	}
}

// ---- pending request store -------------------------------------------------

// handlePending receives a Keep-signed pending escalation JWT from Gate.
// Guard validates the JWT signature (preventing rogue Gate instances from
// registering arbitrary JWTs), then stores it keyed by JTI. handleGet can
// then look up the JWT from a short ?jti= URL instead of requiring the full
// JWT in the query string.
// POST /pending  body: {"jti": "...", "jwt": "..."}
// Requires bearer auth.
func (s *Server) handlePending(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Limits.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.Limits.MaxRequestBodyBytes))
	}

	var body struct {
		JTI string `json:"jti"`
		JWT string `json:"jwt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.JTI == "" || body.JWT == "" {
		http.Error(w, "jti and jwt are required", http.StatusBadRequest)
		return
	}

	if err := shared.CheckFields([]shared.FieldCheck{
		{body.JTI, "jti", s.cfg.Limits.MaxJTIBytes},
		{body.JWT, "jwt", s.cfg.Limits.MaxPendingJWTBytes},
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate the JWT signature to prevent rogue Gate instances from
	// registering arbitrary JWTs and granting themselves escalation tokens.
	claims, err := s.verifyRequest(body.JWT)
	if err != nil {
		slog.Warn("pending: invalid escalation request JWT",
			"error", err, "jti", body.JTI, "remote", r.RemoteAddr)
		http.Error(w, "invalid or expired escalation JWT", http.StatusUnauthorized)
		return
	}

	// Verify the JTI in the body matches the JWT's own jti claim.
	if claims.ID != body.JTI {
		slog.Warn("pending: JTI mismatch",
			"body_jti", body.JTI, "jwt_jti", claims.ID, "remote", r.RemoteAddr)
		http.Error(w, "jti does not match JWT id claim", http.StatusBadRequest)
		return
	}

	expiry := time.Now().Add(s.ttl)
	if claims.ExpiresAt != nil {
		expiry = claims.ExpiresAt.Time
	}

	if err := s.pending.StorePending(r.Context(), PendingRequest{
		JTI:       body.JTI,
		JWT:       body.JWT,
		ExpiresAt: expiry,
	}); err != nil {
		if errors.Is(err, ErrCapacityExceeded) {
			slog.ErrorContext(r.Context(), "pending requests at capacity", "jti", body.JTI)
			http.Error(w, "server at capacity", http.StatusServiceUnavailable)
			return
		}
		slog.Error("store pending request", "error", err, "jti", body.JTI)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("escalation request registered via proactive push",
		"jti", body.JTI,
		"user_id", claims.UserID,
		"server", claims.Server,
		"tool", claims.Tool,
		"remote", r.RemoteAddr,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "registered", "jti": body.JTI})
}

// cleanupWorker periodically removes expired unclaimed tokens.
func (s *Server) cleanupWorker(ctx context.Context) {
	interval := 300 * time.Second
	if s.cfg.TokenStore.CleanupInterval > 0 {
		interval = time.Duration(s.cfg.TokenStore.CleanupInterval) * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanupExpired()
		}
	}
}

func (s *Server) cleanupExpired() {
	ctx := context.Background()
	if err := s.pending.PurgeExpired(ctx); err != nil {
		slog.Warn("purge expired pending requests", "error", err)
	}
	if err := s.unclaimed.PurgeExpired(ctx); err != nil {
		slog.Warn("purge expired unclaimed tokens", "error", err)
	}
}

// handleHealthz is the liveness probe. Returns 200 as long as the HTTP server
// is running and able to handle requests.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleReadyz is the readiness probe. Returns 200 when Guard is fully
// initialized: signing keys are loaded, templates are parsed, and both
// listeners are bound and serving.
func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if len(s.keepKey) == 0 || len(s.signingKey) == 0 || s.templates == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "unavailable",
			"reason": "signing keys or templates not initialized",
		})
		return
	}
	if !s.uiReady.Load() || !s.apiReady.Load() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "unavailable",
			"reason": "listeners not yet ready",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}


// handleTokenUnclaimedList returns the list of unclaimed tokens for a given user.
// GET /token/unclaimed/list?user_id={userID}
// Called by Gate (bearer auth) and by remote workflow agents (e.g. ServiceNow).
func (s *Server) handleTokenUnclaimedList(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	tokens, err := s.unclaimed.ListUnclaimed(r.Context(), userID)
	if err != nil {
		slog.Error("list unclaimed tokens", "error", err, "user_id", userID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	result := make([]struct {
		JTI       string    `json:"jti"`
		Raw       string    `json:"raw"`
		ExpiresAt time.Time `json:"expires_at"`
	}, 0, len(tokens))
	for _, tok := range tokens {
		result = append(result, struct {
			JTI       string    `json:"jti"`
			Raw       string    `json:"raw"`
			ExpiresAt time.Time `json:"expires_at"`
		}{JTI: tok.JTI, Raw: tok.Raw, ExpiresAt: tok.ExpiresAt})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// handleTokenDeposit accepts a Keep-signed pending escalation JWT from a remote
// workflow system (e.g. ServiceNow). Guard validates it, issues an escalation
// token, and adds it to the unclaimed list for Gate to collect via polling.
// POST /token/deposit  body: {"pending_jwt": "...", "user_id": "..."}
func (s *Server) handleTokenDeposit(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Limits.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.Limits.MaxRequestBodyBytes))
	}

	var body struct {
		PendingJWT string `json:"pending_jwt"`
		UserID     string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.PendingJWT == "" || body.UserID == "" {
		http.Error(w, "pending_jwt and user_id are required", http.StatusBadRequest)
		return
	}

	if err := shared.CheckFields([]shared.FieldCheck{
		{body.UserID, "user_id", s.cfg.Limits.MaxUserIDBytes},
		{body.PendingJWT, "pending_jwt", s.cfg.Limits.MaxPendingJWTBytes},
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	claims, err := s.verifyRequest(body.PendingJWT)
	if err != nil {
		slog.Warn("deposit: invalid pending escalation JWT", "error", err, "user_id", body.UserID, "remote", r.RemoteAddr)
		http.Error(w, "invalid or expired pending JWT", http.StatusUnauthorized)
		return
	}

	// Validate that the user_id in the body matches the uid in the JWT.
	if !strings.EqualFold(claims.UserID, body.UserID) {
		slog.Warn("deposit: user_id mismatch", "jwt_uid", claims.UserID, "body_uid", body.UserID)
		http.Error(w, "user_id does not match JWT uid claim", http.StatusBadRequest)
		return
	}

	escalationToken, expiry, err := s.issueEscalationToken(claims, claims.ID, claims.EscalationScope)
	if err != nil {
		slog.Error("deposit: issue escalation token", "error", err)
		http.Error(w, "failed to generate escalation token", http.StatusInternalServerError)
		return
	}

	if err := s.unclaimed.AddUnclaimed(r.Context(), UnclaimedToken{
		UserID:    claims.UserID,
		JTI:       claims.ID,
		Raw:       escalationToken,
		ExpiresAt: expiry,
	}); err != nil {
		if errors.Is(err, ErrCapacityExceeded) {
			slog.ErrorContext(r.Context(), "unclaimed tokens at capacity",
				"user_id", claims.UserID, "jti", claims.ID)
			http.Error(w, "server at capacity", http.StatusServiceUnavailable)
			return
		}
		slog.Error("add unclaimed token via deposit", "error", err, "jti", claims.ID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("escalation token deposited via workflow",
		"user_id", claims.UserID,
		"server", claims.Server,
		"tool", claims.Tool,
		"jti", claims.ID,
		"expires_at", expiry.UTC().Format(time.RFC3339),
		"remote", r.RemoteAddr,
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "deposited",
		"jti":    claims.ID,
	})
}

// handleTokenClaim atomically removes and returns the unclaimed token identified
// by jti. Returns 404 when the token is not in the unclaimed list (either not yet
// approved, already claimed, or expired). Each token may only be claimed once.
// POST /token/claim  body: {"jti": "..."}
func (s *Server) handleTokenClaim(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Limits.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.Limits.MaxRequestBodyBytes))
	}

	var body struct {
		JTI string `json:"jti"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.JTI == "" {
		http.Error(w, "jti is required", http.StatusBadRequest)
		return
	}

	if err := shared.CheckLen(body.JTI, "jti", s.cfg.Limits.MaxJTIBytes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	found, err := s.unclaimed.ClaimToken(r.Context(), body.JTI)
	if err != nil {
		slog.Error("claim token", "error", err, "jti", body.JTI)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if found == nil {
		// Not yet approved, already claimed, or expired — not an error from
		// Gate's perspective; Gate will retry on the next tool call.
		http.NotFound(w, r)
		return
	}

	slog.Info("escalation token claimed",
		"jti", body.JTI,
		"user_id", found.UserID,
		"remote_addr", r.RemoteAddr,
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"raw": found.Raw,
	})
}

// ---- template data types ---------------------------------------------------

type approvalPageData struct {
	UserID          string
	UserDisplayName string
	Server          string
	Tool            string
	Reason          string
	ScopeJSON       string
	Token           string
}

type tokenPageData struct {
	Server          string
	Tool            string
	EscalationToken string
	GateURL         string
}
