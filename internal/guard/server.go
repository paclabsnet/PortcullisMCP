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
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	"github.com/paclabsnet/PortcullisMCP/internal/shared/tlsutil"
)

//go:embed templates/*
var templatesFS embed.FS

// Server is the portcullis-guard HTTP server.
type Server struct {
	cfg            Config
	pendingStore   PendingStore
	unclaimedStore UnclaimedStore
	templates      *template.Template

	keepKey    []byte
	signingKey []byte
	ttl        time.Duration

	// uiReady and apiReady are set to true once each listener is successfully bound.
	uiReady  atomic.Bool
	apiReady atomic.Bool
}

// NewServer creates a Guard server.
func NewServer(ctx context.Context, cfg Config) (*Server, error) {
	if _, err := cfg.Validate(nil); err != nil {
		return nil, err
	}

	var pending PendingStore
	var unclaimed UnclaimedStore

	switch cfg.Operations.Storage.Backend {
	case "redis":
		var redisCfg RedisConfig
		if err := mapstructure.Decode(cfg.Operations.Storage.Config, &redisCfg); err != nil {
			return nil, fmt.Errorf("decode redis config: %w", err)
		}
		client, err := NewRedisClient(ctx, redisCfg)
		if err != nil {
			return nil, err
		}
		pending = NewRedisPendingStore(client, redisCfg.KeyPrefix)
		unclaimed = NewRedisUnclaimedStore(client, redisCfg.KeyPrefix, cfg.Limits.MaxUnclaimedPerUser)
	case "memory", "":
		m := NewMemStore(cfg.Limits.MaxPendingRequests, cfg.Limits.MaxUnclaimedTotal, cfg.Limits.MaxUnclaimedPerUser)
		pending = m
		unclaimed = m
	default:
		return nil, fmt.Errorf("unknown storage backend %q", cfg.Operations.Storage.Backend)
	}

	tmpl := template.New("")
	if cfg.Responsibility.Interface.Templates != "" {
		expanded, err := expandHome(cfg.Responsibility.Interface.Templates)
		if err != nil {
			return nil, fmt.Errorf("expand templates path: %w", err)
		}
		tmpl, err = tmpl.ParseGlob(expanded + "/*.html")
		if err != nil {
			return nil, fmt.Errorf("parse templates from %q: %w", expanded, err)
		}
	} else {
		var err error
		tmpl, err = tmpl.ParseFS(templatesFS, "templates/*.html")
		if err != nil {
			return nil, fmt.Errorf("parse built-in templates: %w", err)
		}
	}

	ttl := time.Duration(cfg.Responsibility.Issuance.TokenTTL) * time.Second
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	return &Server{
		cfg:            cfg,
		pendingStore:   pending,
		unclaimedStore: unclaimed,
		templates:      tmpl,
		keepKey:        []byte(cfg.Responsibility.Issuance.ApprovalRequestVerificationKey),
		signingKey:     []byte(cfg.Responsibility.Issuance.SigningKey),
		ttl:            ttl,
	}, nil
}

// expandHome replaces ~ at the start of a path with the user's home directory.
func expandHome(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return home + path[1:], nil
}

// Run starts the UI and API listeners and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	uiEndpoint, ok := s.cfg.Server.Endpoints["approval_ui"]
	if !ok {
		return fmt.Errorf("server.endpoints.approval_ui is required")
	}
	apiEndpoint, ok := s.cfg.Server.Endpoints["token_api"]
	if !ok {
		return fmt.Errorf("server.endpoints.token_api is required")
	}

	uiMux := http.NewServeMux()
	uiMux.HandleFunc("GET /healthz", s.handleHealthz)
	uiMux.HandleFunc("GET /readyz", s.handleReadyz)
	uiMux.HandleFunc("GET /approve", s.handleApprovePage)
	uiMux.HandleFunc("POST /approve", s.handleApproveAction)

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("GET /healthz", s.handleHealthz)
	apiMux.HandleFunc("GET /readyz", s.handleReadyz)
	apiMux.Handle("GET /token/unclaimed/list", s.machineAuthMiddleware(s.handleTokenUnclaimedList))
	apiMux.Handle("POST /token/deposit", s.machineAuthMiddleware(s.handleTokenDeposit))
	apiMux.Handle("POST /token/claim", s.machineAuthMiddleware(s.handleTokenClaim))
	apiMux.Handle("POST /pending", s.machineAuthMiddleware(s.handlePendingStore))

	go s.cleanupWorker(ctx)

	uiSrv := &http.Server{
		Addr:    uiEndpoint.Listen,
		Handler: uiMux,
	}

	apiSrv := &http.Server{
		Addr:    apiEndpoint.Listen,
		Handler: apiMux,
	}

	// Apply TLS if configured
	if uiEndpoint.TLS.Cert != "" {
		tlsCfg, err := tlsutil.BuildServerTLS(uiEndpoint.TLS)
		if err != nil {
			return fmt.Errorf("ui tls: %w", err)
		}
		uiSrv.TLSConfig = tlsCfg
	}

	if apiEndpoint.TLS.Cert != "" {
		tlsCfg, err := tlsutil.BuildServerTLS(apiEndpoint.TLS)
		if err != nil {
			return fmt.Errorf("api tls: %w", err)
		}
		apiSrv.TLSConfig = tlsCfg
	}

	errChan := make(chan error, 2)
	var wg sync.WaitGroup

	// Start UI server
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		if uiSrv.TLSConfig != nil {
			slog.Info("guard ui listening (HTTPS)", "addr", uiEndpoint.Listen)
			err = uiSrv.ListenAndServeTLS("", "")
		} else {
			slog.Warn("guard ui listening (HTTP - no TLS)", "addr", uiEndpoint.Listen)
			err = uiSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- fmt.Errorf("ui server: %w", err)
		}
	}()

	// Start API server
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		if apiSrv.TLSConfig != nil {
			slog.Info("guard api listening (HTTPS)", "addr", apiEndpoint.Listen)
			err = apiSrv.ListenAndServeTLS("", "")
		} else {
			slog.Warn("guard api listening (HTTP - no TLS)", "addr", apiEndpoint.Listen)
			err = apiSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- fmt.Errorf("api server: %w", err)
		}
	}()

	s.uiReady.Store(true)
	s.apiReady.Store(true)

	// Shutdown handling
	go func() {
		<-ctx.Done()
		slog.Info("shutting down guard servers")
		_ = uiSrv.Shutdown(context.Background())
		_ = apiSrv.Shutdown(context.Background())
	}()

	// Wait for error or cancellation
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		wg.Wait()
		return nil
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

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
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) machineAuthMiddleware(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiEndpoint := s.cfg.Server.Endpoints["token_api"]

		// 1. Check mTLS if configured
		if apiEndpoint.TLS.ClientCA != "" && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			next.ServeHTTP(w, r)
			return
		}

		// 2. Check Bearer Token
		if apiEndpoint.Auth.Credentials.BearerToken != "" {
			auth := r.Header.Get("Authorization")
			expected := "Bearer " + apiEndpoint.Auth.Credentials.BearerToken
			if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Bearer realm="portcullis-guard"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// verifyRequest parses and verifies a Keep-signed escalation request JWT.
func (s *Server) verifyRequest(tokenStr string) (*shared.EscalationRequestClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &shared.EscalationRequestClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.keepKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	claims, ok := token.Claims.(*shared.EscalationRequestClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}

// issueEscalationToken signs a new escalation token granting scope.
func (s *Server) issueEscalationToken(claims *shared.EscalationRequestClaims, requestJTI string, scope []map[string]any) (string, time.Time, error) {
	now := time.Now()
	expiry := now.Add(s.ttl)

	jti := requestJTI
	if jti == "" {
		jti = uuid.NewString()
	}

	actor := claims.DisplayName
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

func (s *Server) handleApprovePage(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		jti := r.URL.Query().Get("jti")
		if jti == "" {
			http.Error(w, "missing token or jti", http.StatusBadRequest)
			return
		}
		pr, ok, err := s.pendingStore.GetPending(r.Context(), jti)
		if err != nil {
			slog.Error("pending store lookup", "error", err, "jti", jti)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "escalation request not found or expired", http.StatusNotFound)
			return
		}
		tokenStr = pr.JWT
	}
	claims, err := s.verifyRequest(tokenStr)
	if err != nil {
		http.Error(w, "invalid or expired approval link", http.StatusUnauthorized)
		return
	}

	scopeJSON, _ := json.MarshalIndent(claims.Scope, "", "  ")
	data := approvalPageData{
		UserID:          claims.UserID,
		UserDisplayName: claims.DisplayName,
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

func (s *Server) handleApproveAction(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "invalid or expired approval link", http.StatusUnauthorized)
		return
	}

	scope := claims.Scope
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
	}

	escalationToken, expiry, err := s.issueEscalationToken(claims, claims.ID, scope)
	if err != nil {
		http.Error(w, "failed to generate escalation token", http.StatusInternalServerError)
		return
	}

	_ = s.unclaimedStore.AddUnclaimed(r.Context(), UnclaimedToken{
		UserID:    claims.UserID,
		JTI:       claims.ID,
		Raw:       escalationToken,
		ExpiresAt: expiry,
	})

	gatePort := s.cfg.Responsibility.Interface.GateManagementPort
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
	_ = s.templates.ExecuteTemplate(w, "token.html", data)
}

func (s *Server) handlePendingStore(w http.ResponseWriter, r *http.Request) {
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

	if err := shared.CheckFields([]shared.FieldCheck{
		{Value: body.JTI, Name: "jti", Max: s.cfg.Limits.MaxJTIBytes},
		{Value: body.JWT, Name: "jwt", Max: s.cfg.Limits.MaxPendingJWTBytes},
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	claims, err := s.verifyRequest(body.JWT)
	if err != nil {
		http.Error(w, "invalid or expired escalation JWT", http.StatusUnauthorized)
		return
	}

	if claims.ID != body.JTI {
		http.Error(w, "jti does not match JWT id claim", http.StatusBadRequest)
		return
	}

	expiry := time.Now().Add(s.ttl)
	if claims.ExpiresAt != nil {
		expiry = claims.ExpiresAt.Time
	}

	if err := s.pendingStore.StorePending(r.Context(), PendingRequest{
		JTI:       body.JTI,
		JWT:       body.JWT,
		ExpiresAt: expiry,
	}); err != nil {
		http.Error(w, "failed to store pending request", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "registered", "jti": body.JTI})
}

func (s *Server) handleTokenUnclaimedList(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	if err := shared.CheckLen(userID, "user_id", s.cfg.Limits.MaxUserIDBytes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tokens, err := s.unclaimedStore.ListUnclaimed(r.Context(), userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, tokens)
}

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
		{Value: body.UserID, Name: "user_id", Max: s.cfg.Limits.MaxUserIDBytes},
		{Value: body.PendingJWT, Name: "pending_jwt", Max: s.cfg.Limits.MaxPendingJWTBytes},
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	claims, err := s.verifyRequest(body.PendingJWT)
	if err != nil {
		http.Error(w, "invalid or expired pending JWT", http.StatusUnauthorized)
		return
	}

	if !strings.EqualFold(claims.UserID, body.UserID) {
		http.Error(w, "user_id does not match JWT uid claim", http.StatusBadRequest)
		return
	}

	escalationToken, expiry, err := s.issueEscalationToken(claims, claims.ID, claims.Scope)
	if err != nil {
		http.Error(w, "failed to generate escalation token", http.StatusInternalServerError)
		return
	}

	_ = s.unclaimedStore.AddUnclaimed(r.Context(), UnclaimedToken{
		UserID:    claims.UserID,
		JTI:       claims.ID,
		Raw:       escalationToken,
		ExpiresAt: expiry,
	})

	writeJSON(w, http.StatusCreated, map[string]string{"status": "deposited", "jti": claims.ID})
}

func (s *Server) handleTokenClaim(w http.ResponseWriter, r *http.Request) {
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

	found, err := s.unclaimedStore.ClaimToken(r.Context(), body.JTI)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if found == nil {
		http.NotFound(w, r)
		return
	}

	slog.Info("escalation token claimed", "jti", body.JTI, "user_id", found.UserID, "remote_addr", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]string{"raw": found.Raw})
}

func (s *Server) cleanupWorker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.pendingStore.PurgeExpired(ctx)
			_ = s.unclaimedStore.PurgeExpired(ctx)
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

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
