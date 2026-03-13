package gate

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

//go:embed web/index.html
var uiHTML []byte

// ManagementServer is a localhost-only HTTP server for escalation token CRUD,
// OIDC token updates, and the management UI at GET /.
// By default no authentication is required; set cfg.SharedSecret to require
// a bearer token on all API requests (the UI itself is always served without auth).
type ManagementServer struct {
	store    *TokenStore
	identity *IdentityCache
	cfg      MgmtAPIConfig
	server   *http.Server
}

// NewManagementServer creates a ManagementServer but does not start it.
func NewManagementServer(store *TokenStore, identity *IdentityCache, cfg MgmtAPIConfig) *ManagementServer {
	ms := &ManagementServer{store: store, identity: identity, cfg: cfg}
	mux := http.NewServeMux()

	// UI — always served without auth so the browser can load it.
	// Use "GET /{$}" (Go 1.22+ exact-root match) to avoid conflicting
	// with the method-agnostic "/tokens" and "/identity" registrations below.
	mux.HandleFunc("GET /{$}", ms.handleUI)

	// API — optionally protected by shared secret.
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("GET /tokens", ms.handleList)
	apiMux.HandleFunc("POST /tokens", ms.handleAdd)
	apiMux.HandleFunc("DELETE /tokens/{id}", ms.handleDelete)
	apiMux.HandleFunc("GET /identity", ms.handleIdentityGet)
	apiMux.HandleFunc("PUT /identity/token", ms.handleIdentityTokenUpdate)

	var apiHandler http.Handler = apiMux
	if cfg.SharedSecret != "" {
		apiHandler = ms.requireSecret(apiMux)
	}
	mux.Handle("/tokens", apiHandler)
	mux.Handle("/tokens/", apiHandler)
	mux.Handle("/identity", apiHandler)
	mux.Handle("/identity/", apiHandler)

	ms.server = &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", cfg.Port),
		Handler: mux,
	}
	return ms
}

// Start begins listening. It returns after the listener is bound.
func (ms *ManagementServer) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", ms.server.Addr)
	if err != nil {
		return fmt.Errorf("management api listen: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = ms.server.Shutdown(context.Background())
	}()
	go func() { _ = ms.server.Serve(ln) }()
	return nil
}

func (ms *ManagementServer) handleUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(uiHTML)
}

func (ms *ManagementServer) handleList(w http.ResponseWriter, r *http.Request) {
	tokens := ms.store.All()
	type item struct {
		TokenID   string `json:"token_id"`
		GrantedBy string `json:"granted_by"`
	}
	out := make([]item, len(tokens))
	for i, t := range tokens {
		out[i] = item{TokenID: t.TokenID, GrantedBy: t.GrantedBy}
	}
	writeJSON(w, http.StatusOK, out)
}

func (ms *ManagementServer) handleAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	tok, err := ms.store.Add(r.Context(), body.Token)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"token_id":   tok.TokenID,
		"granted_by": tok.GrantedBy,
	})
}

func (ms *ManagementServer) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := ms.store.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (ms *ManagementServer) handleIdentityGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, ms.identity.Info())
}

func (ms *ManagementServer) handleIdentityTokenUpdate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	id, err := ms.identity.UpdateToken(body.Token)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"user_id":     id.UserID,
		"source_type": id.SourceType,
	})
}

func (ms *ManagementServer) requireSecret(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + ms.cfg.SharedSecret
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
