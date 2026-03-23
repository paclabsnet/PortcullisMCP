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
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
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
	if cfg.Port == 0 {
		cfg.Port = 7777
	}
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

// Start begins listening on both IPv4 and IPv6 loopback addresses so that
// http://localhost:<port> works regardless of how the OS resolves "localhost"
// (Windows commonly prefers ::1; Linux/macOS commonly prefer 127.0.0.1).
func (ms *ManagementServer) Start(ctx context.Context) error {
	addrs := []string{
		fmt.Sprintf("127.0.0.1:%d", ms.cfg.Port),
		fmt.Sprintf("[::1]:%d", ms.cfg.Port),
	}

	started := 0
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			// Not all systems have IPv6 loopback; skip silently.
			continue
		}
		go func() { _ = ms.server.Serve(ln) }()
		started++
	}
	if started == 0 {
		return fmt.Errorf("management api: could not listen on any loopback address on port %d", ms.cfg.Port)
	}

	go func() {
		<-ctx.Done()
		_ = ms.server.Shutdown(context.Background())
	}()
	return nil
}

func (ms *ManagementServer) handleUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(uiHTML)
}

func (ms *ManagementServer) handleList(w http.ResponseWriter, _ *http.Request) {
	tokens := ms.store.All()
	type portcullisClaims struct {
		ArgRestrictions []map[string]any `json:"arg_restrictions,omitempty"`
		Tools           []string         `json:"tools,omitempty"`
		Services        []string         `json:"services,omitempty"`
	}
	type item struct {
		TokenID    string           `json:"token_id"`
		GrantedBy  string           `json:"granted_by,omitempty"`
		Subject    string           `json:"subject,omitempty"`
		Expiry     string           `json:"expiry,omitempty"`
		Portcullis portcullisClaims `json:"portcullis,omitempty"`
	}
	out := make([]item, len(tokens))
	for i, t := range tokens {
		it := item{TokenID: t.TokenID, GrantedBy: t.GrantedBy}
		if claims, err := unsafeParseJWTClaims(t.Raw); err == nil {
			if exp, ok := claims["exp"].(float64); ok {
				it.Expiry = time.Unix(int64(exp), 0).Local().Format("2006-01-02 15:04:05")
			}
			if sub, ok := claims["sub"].(string); ok && sub != t.TokenID {
				it.Subject = sub
			}
			if pc, ok := claims["portcullis"].(map[string]any); ok {
				if v, ok := pc["tools"].([]any); ok {
					for _, s := range v {
						if str, ok := s.(string); ok {
							it.Portcullis.Tools = append(it.Portcullis.Tools, str)
						}
					}
				}
				if v, ok := pc["services"].([]any); ok {
					for _, s := range v {
						if str, ok := s.(string); ok {
							it.Portcullis.Services = append(it.Portcullis.Services, str)
						}
					}
				}
				if v, ok := pc["arg_restrictions"].([]any); ok {
					for _, r := range v {
						if m, ok := r.(map[string]any); ok {
							it.Portcullis.ArgRestrictions = append(it.Portcullis.ArgRestrictions, m)
						}
					}
				}
			}
		}
		out[i] = it
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
