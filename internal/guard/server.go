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
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
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

// unclaimedToken is a Guard-issued escalation token that has been approved but
// not yet collected by Gate. Keyed by JTI in the unclaimedTokens map.
type unclaimedToken struct {
	UserID    string
	JTI       string
	Raw       string
	ExpiresAt time.Time
}

// pendingRequest is a Keep-signed escalation request JWT that Gate has pushed
// to Guard proactively (via POST /pending). Stored so that handleGet can look
// up the JWT by JTI and serve the approval page via a short ?jti= URL.
type pendingRequest struct {
	JTI       string
	JWT       string
	ExpiresAt time.Time
}

// Server is the portcullis-guard HTTP server.
type Server struct {
	cfg        Config
	keepKey    []byte
	signingKey []byte
	ttl        time.Duration
	templates  *template.Template

	// unclaimedTokens holds approved escalation tokens not yet claimed by Gate.
	// Outer key: UserID. Inner key: JTI.
	unclaimedMu     sync.Mutex
	unclaimedTokens map[string]map[string]unclaimedToken

	// pendingRequests holds Keep-signed escalation request JWTs pushed by Gate
	// in proactive mode. Keyed by JTI. Cleaned up after expiry.
	pendingMu       sync.Mutex
	pendingRequests map[string]pendingRequest
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
	if cfg.Auth.BearerToken == "" && cfg.Auth.AllowUnauthenticatedTokenAPIs {
		slog.Warn("Guard token APIs are running without authentication — do not use in production",
			"affected_endpoints", []string{"/token/unclaimed/list", "/token/deposit", "/pending"})
	}

	ttl := time.Duration(cfg.EscalationTokenSigning.TTL) * time.Second
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	tmpl, err := loadTemplates(cfg.Templates.Dir)
	if err != nil {
		return nil, fmt.Errorf("load templates: %w", err)
	}

	return &Server{
		cfg:             cfg,
		keepKey:         []byte(cfg.Keep.PendingEscalationRequestSigningKey),
		signingKey:      []byte(cfg.EscalationTokenSigning.Key),
		ttl:             ttl,
		templates:       tmpl,
		unclaimedTokens: make(map[string]map[string]unclaimedToken),
		pendingRequests: make(map[string]pendingRequest),
	}, nil
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

// Run starts the HTTP server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("GET /approve", s.handleGet)
	mux.HandleFunc("POST /approve", s.handlePost)

	// Token API endpoints — used by Gate to claim approved tokens.
	// /token/unclaimed/list, /token/deposit, and /pending require bearer auth.
	// /token/claim does not require auth: the JTI acts as a capability token.
	// An attacker would need to already know the random UUID JTI to attempt a
	// claim, and the resulting token is still validated by the PDP.
	mux.HandleFunc("GET /token/unclaimed/list", s.requireTokenAuth(s.handleTokenUnclaimedList))
	mux.HandleFunc("POST /token/deposit", s.requireTokenAuth(s.handleTokenDeposit))
	mux.HandleFunc("POST /token/claim", s.handleTokenClaim)
	// Proactive mode: Gate registers the pending escalation JWT before presenting
	// the approval URL to the user, so the URL can be shortened to ?jti=<uuid>.
	mux.HandleFunc("POST /pending", s.requireTokenAuth(s.handlePending))

	// Start background cleanup of expired unclaimed tokens.
	go s.cleanupWorker(ctx)

	srv := &http.Server{
		Addr:    s.cfg.Listen.Address,
		Handler: mux,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	slog.Info("portcullis-guard listening", "addr", s.cfg.Listen.Address)
	return srv.ListenAndServe()
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
			Issuer:    "portcullis-guard",
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
		s.pendingMu.Lock()
		pr, ok := s.pendingRequests[jti]
		s.pendingMu.Unlock()
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
	s.addUnclaimed(claims.UserID, claims.ID, escalationToken, expiry)

	scopeJSON, _ := json.Marshal(scope)
	slog.Info("escalation token issued",
		"user_id", claims.UserID,
		"user_display_name", claims.UserDisplayName,
		"server", claims.Server,
		"tool", claims.Tool,
		"reason", claims.Reason,
		"escalation_scope", string(scopeJSON),
		"jti", claims.ID,
		"issuer", "portcullis-guard",
		"expires_at", expiry.UTC().Format(time.RFC3339),
		"remote", r.RemoteAddr,
	)

	gatePort := s.cfg.PortcullisGateManagementPort
	if gatePort == 0 {
		gatePort = 7777
	}
	data := tokenPageData{
		Server:          claims.Server,
		Tool:            claims.Tool,
		EscalationToken: escalationToken,
		GateURL:         fmt.Sprintf("http://localhost:%d", gatePort),
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

	// Cap applies to in-memory storage only; replace with cache-side enforcement when switching to distributed token store.
	s.pendingMu.Lock()
	if s.cfg.Limits.MaxPendingRequests > 0 && len(s.pendingRequests) >= s.cfg.Limits.MaxPendingRequests {
		s.pendingMu.Unlock()
		slog.ErrorContext(r.Context(), "pending requests at capacity", "limit", s.cfg.Limits.MaxPendingRequests)
		http.Error(w, "server at capacity", http.StatusServiceUnavailable)
		return
	}
	s.pendingRequests[body.JTI] = pendingRequest{
		JTI:       body.JTI,
		JWT:       body.JWT,
		ExpiresAt: expiry,
	}
	s.pendingMu.Unlock()

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

// ---- unclaimed token store -------------------------------------------------

// addUnclaimed adds an approved escalation token to the unclaimed list for userID.
func (s *Server) addUnclaimed(userID, jti, raw string, expiresAt time.Time) {
	s.unclaimedMu.Lock()
	defer s.unclaimedMu.Unlock()

	if s.unclaimedTokens[userID] == nil {
		s.unclaimedTokens[userID] = make(map[string]unclaimedToken)
	}
	s.unclaimedTokens[userID][jti] = unclaimedToken{
		UserID:    userID,
		JTI:       jti,
		Raw:       raw,
		ExpiresAt: expiresAt,
	}
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
	now := time.Now()

	s.unclaimedMu.Lock()
	for userID, tokens := range s.unclaimedTokens {
		for jti, tok := range tokens {
			if tok.ExpiresAt.Before(now) {
				delete(tokens, jti)
			}
		}
		if len(tokens) == 0 {
			delete(s.unclaimedTokens, userID)
		}
	}
	s.unclaimedMu.Unlock()

	s.pendingMu.Lock()
	for jti, pr := range s.pendingRequests {
		if pr.ExpiresAt.Before(now) {
			delete(s.pendingRequests, jti)
		}
	}
	s.pendingMu.Unlock()
}

// handleHealthz is the liveness probe. Returns 200 as long as the HTTP server
// is running and able to handle requests.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleReadyz is the readiness probe. Returns 200 when Guard is fully
// initialized: signing keys are loaded and templates are parsed.
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}

// requireTokenAuth is middleware that requires a valid bearer token for the
// /token/unclaimed/list, /token/deposit, and /pending endpoints.
func (s *Server) requireTokenAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Auth.BearerToken == "" {
			if s.cfg.Auth.AllowUnauthenticatedTokenAPIs {
				next(w, r)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.Auth.BearerToken
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			slog.Warn("unauthorized token API request", "remote", r.RemoteAddr, "path", r.URL.Path)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
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

	s.unclaimedMu.Lock()
	userTokens := s.unclaimedTokens[userID]
	result := make([]struct {
		JTI       string    `json:"jti"`
		Raw       string    `json:"raw"`
		ExpiresAt time.Time `json:"expires_at"`
	}, 0, len(userTokens))
	for _, tok := range userTokens {
		result = append(result, struct {
			JTI       string    `json:"jti"`
			Raw       string    `json:"raw"`
			ExpiresAt time.Time `json:"expires_at"`
		}{JTI: tok.JTI, Raw: tok.Raw, ExpiresAt: tok.ExpiresAt})
	}
	s.unclaimedMu.Unlock()

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

	userID := claims.UserID

	// Cap applies to in-memory storage only; replace with cache-side enforcement when switching to distributed token store.
	s.unclaimedMu.Lock()
	if s.cfg.Limits.MaxUnclaimedPerUser > 0 && len(s.unclaimedTokens[userID]) >= s.cfg.Limits.MaxUnclaimedPerUser {
		s.unclaimedMu.Unlock()
		slog.ErrorContext(r.Context(), "unclaimed tokens at per-user capacity", "user_id", userID, "limit", s.cfg.Limits.MaxUnclaimedPerUser)
		http.Error(w, "server at capacity", http.StatusServiceUnavailable)
		return
	}
	if s.cfg.Limits.MaxUnclaimedTotal > 0 {
		total := 0
		for _, m := range s.unclaimedTokens {
			total += len(m)
		}
		if total >= s.cfg.Limits.MaxUnclaimedTotal {
			s.unclaimedMu.Unlock()
			slog.ErrorContext(r.Context(), "unclaimed tokens at total capacity", "limit", s.cfg.Limits.MaxUnclaimedTotal)
			http.Error(w, "server at capacity", http.StatusServiceUnavailable)
			return
		}
	}
	if s.unclaimedTokens[userID] == nil {
		s.unclaimedTokens[userID] = make(map[string]unclaimedToken)
	}
	s.unclaimedTokens[userID][claims.ID] = unclaimedToken{
		UserID:    userID,
		JTI:       claims.ID,
		Raw:       escalationToken,
		ExpiresAt: expiry,
	}
	s.unclaimedMu.Unlock()

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

	s.unclaimedMu.Lock()
	var found *unclaimedToken
	for _, userTokens := range s.unclaimedTokens {
		if tok, ok := userTokens[body.JTI]; ok {
			cp := tok
			found = &cp
			delete(userTokens, body.JTI)
			break
		}
	}
	s.unclaimedMu.Unlock()

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
