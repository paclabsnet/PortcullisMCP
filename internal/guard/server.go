package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// escalationRequestClaims are the JWT claims Keep embeds in approval URL tokens.
// These must match the claims Keep writes in internal/keep/escalation.go.
type escalationRequestClaims struct {
	jwt.RegisteredClaims
	UserID          string         `json:"uid"`
	UserDisplayName string         `json:"uname,omitempty"`
	Server          string         `json:"srv"`
	Tool            string         `json:"tool"`
	Reason          string         `json:"reason"`
	EscalationScope []map[string]any `json:"scope,omitempty"`
}

// portcullisClaims is the nested object stored under the "portcullis" JWT claim.
// scope carries the PDP-issued escalation scope constraints.
// tools and services record exactly what was approved so the PDP can enforce
// that the token is only used for the escalated operation.
type portcullisClaims struct {
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
}

// NewServer creates a Guard server from config.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Keep.EscalationRequestSigningKey == "" {
		return nil, fmt.Errorf("keep.escalation_request_signing_key is required")
	}
	if cfg.EscalationTokenSigning.Key == "" {
		return nil, fmt.Errorf("escalation_token_signing.key is required")
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
		cfg:        cfg,
		keepKey:    []byte(cfg.Keep.EscalationRequestSigningKey),
		signingKey: []byte(cfg.EscalationTokenSigning.Key),
		ttl:        ttl,
		templates:  tmpl,
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
	mux.HandleFunc("GET /approve", s.handleGet)
	mux.HandleFunc("POST /approve", s.handlePost)

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

// issueEscalationToken signs a new escalation token granting the requested scope.
func (s *Server) issueEscalationToken(claims *escalationRequestClaims) (string, time.Time, error) {
	now := time.Now()
	expiry := now.Add(s.ttl)
	tokenClaims := escalationTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "portcullis-guard",
			Subject:   claims.UserID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiry),
		},
		Portcullis: portcullisClaims{
			ArgRestrictions: claims.EscalationScope,
			Tools:           []string{claims.Tool},
			Services:        []string{claims.Server},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims)
	signed, err := token.SignedString(s.signingKey)
	return signed, expiry, err
}

// handleGet renders the approval page for a Keep-signed escalation request.
func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
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

	escalationToken, expiry, err := s.issueEscalationToken(claims)
	if err != nil {
		slog.Error("issue escalation token", "error", err)
		http.Error(w, "failed to generate escalation token", http.StatusInternalServerError)
		return
	}

	scopeJSON, _ := json.Marshal(claims.EscalationScope)
	slog.Info("escalation token issued",
		"user_id", claims.UserID,
		"user_display_name", claims.UserDisplayName,
		"server", claims.Server,
		"tool", claims.Tool,
		"reason", claims.Reason,
		"escalation_scope", string(scopeJSON),
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
