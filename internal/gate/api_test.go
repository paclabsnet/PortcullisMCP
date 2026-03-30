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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestManagementServer creates a ManagementServer with a real TokenStore
// backed by a temp file, and an OS-sourced IdentityCache.
func newTestManagementServer(t *testing.T, cfg MgmtAPIConfig) *ManagementServer {
	t.Helper()
	storePath := filepath.Join(t.TempDir(), "tokens.json")
	store, err := NewTokenStore(context.Background(), storePath)
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}

	identityCfg := IdentityConfig{Source: "os", UserID: "api-test@example.com"}
	identity, err := NewIdentityCache(context.Background(), identityCfg)
	if err != nil {
		t.Fatalf("NewIdentityCache: %v", err)
	}

	ms, err := NewManagementServer(store, identity, cfg, nil, "")
	if err != nil {
		t.Fatalf("NewManagementServer: %v", err)
	}
	return ms
}

func TestManagementServer_ListTokens_Empty(t *testing.T) {
	ms := newTestManagementServer(t, MgmtAPIConfig{})

	req := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var result []any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty list, got %d items", len(result))
	}
}

func TestManagementServer_AddAndListToken(t *testing.T) {
	ms := newTestManagementServer(t, MgmtAPIConfig{AllowManualTokens: true})

	raw := makeTestJWT(map[string]any{"jti": "api-tok", "exp": futureExp(), "granted_by": "boss@corp.com"})
	body, _ := json.Marshal(map[string]string{"token": raw})

	req := httptest.NewRequest(http.MethodPost, "/tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("add status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var added map[string]string
	json.NewDecoder(w.Body).Decode(&added)
	if added["token_id"] != "api-tok" {
		t.Errorf("token_id = %q, want api-tok", added["token_id"])
	}
	if added["granted_by"] != "boss@corp.com" {
		t.Errorf("granted_by = %q, want boss@corp.com", added["granted_by"])
	}

	// List should now return 1 token.
	req2 := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	w2 := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w2, req2)

	var list []map[string]string
	json.NewDecoder(w2.Body).Decode(&list)
	if len(list) != 1 {
		t.Fatalf("list returned %d items, want 1", len(list))
	}
	if list[0]["token_id"] != "api-tok" {
		t.Errorf("list[0].token_id = %q, want api-tok", list[0]["token_id"])
	}
}

func TestManagementServer_AddToken_InvalidBody(t *testing.T) {
	ms := newTestManagementServer(t, MgmtAPIConfig{AllowManualTokens: true})

	req := httptest.NewRequest(http.MethodPost, "/tokens", bytes.NewReader([]byte("not-json")))
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestManagementServer_AddToken_InvalidToken(t *testing.T) {
	ms := newTestManagementServer(t, MgmtAPIConfig{AllowManualTokens: true})

	body, _ := json.Marshal(map[string]string{"token": "not.a.jwt"})
	req := httptest.NewRequest(http.MethodPost, "/tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestManagementServer_DeleteToken(t *testing.T) {
	ms := newTestManagementServer(t, MgmtAPIConfig{AllowManualTokens: true})

	// Add a token first.
	raw := makeTestJWT(map[string]any{"jti": "del-api", "exp": futureExp()})
	addBody, _ := json.Marshal(map[string]string{"token": raw})
	addReq := httptest.NewRequest(http.MethodPost, "/tokens", bytes.NewReader(addBody))
	addReq.Header.Set("Content-Type", "application/json")
	ms.server.Handler.ServeHTTP(httptest.NewRecorder(), addReq)

	// Delete it.
	delReq := httptest.NewRequest(http.MethodDelete, "/tokens/del-api", nil)
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, delReq)

	if w.Code != http.StatusNoContent {
		t.Errorf("delete status = %d, want %d", w.Code, http.StatusNoContent)
	}

	// List should be empty again.
	listReq := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	lw := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(lw, listReq)

	var list []any
	json.NewDecoder(lw.Body).Decode(&list)
	if len(list) != 0 {
		t.Errorf("expected empty list after delete, got %d items", len(list))
	}
}

func TestManagementServer_DeleteToken_NotFound(t *testing.T) {
	ms := newTestManagementServer(t, MgmtAPIConfig{})

	req := httptest.NewRequest(http.MethodDelete, "/tokens/nonexistent", nil)
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestManagementServer_GetIdentity(t *testing.T) {
	ms := newTestManagementServer(t, MgmtAPIConfig{})

	req := httptest.NewRequest(http.MethodGet, "/identity", nil)
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var info map[string]any
	json.NewDecoder(w.Body).Decode(&info)
	if info["user_id"] != "api-test@example.com" {
		t.Errorf("user_id = %v, want api-test@example.com", info["user_id"])
	}
	if info["source_type"] != "os" {
		t.Errorf("source_type = %v, want os", info["source_type"])
	}
}

func TestManagementServer_UpdateIdentityToken(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "oidc-token")

	initialRaw := makeTestJWT(map[string]any{"sub": "old@corp.com", "exp": futureExp()})
	os.WriteFile(tokenFile, []byte(initialRaw), 0600)

	identityCfg := IdentityConfig{
		Source:   "oidc-file",
		OIDCFile: OIDCFileConfig{TokenFile: tokenFile},
	}
	identity, _ := NewIdentityCache(context.Background(), identityCfg)

	storePath := filepath.Join(dir, "tokens.json")
	store, _ := NewTokenStore(context.Background(), storePath)
	ms, err := NewManagementServer(store, identity, MgmtAPIConfig{}, nil, "")
	if err != nil {
		t.Fatalf("NewManagementServer: %v", err)
	}

	newRaw := makeTestJWT(map[string]any{"sub": "new@corp.com", "exp": futureExp()})
	body, _ := json.Marshal(map[string]string{"token": newRaw})
	req := httptest.NewRequest(http.MethodPut, "/identity/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["user_id"] != "new@corp.com" {
		t.Errorf("user_id = %q, want new@corp.com", result["user_id"])
	}
}

func TestManagementServer_UpdateIdentityToken_OSSource(t *testing.T) {
	ms := newTestManagementServer(t, MgmtAPIConfig{})

	body, _ := json.Marshal(map[string]string{"token": "any"})
	req := httptest.NewRequest(http.MethodPut, "/identity/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	// OS source cannot accept a token update.
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestManagementServer_UpdateIdentityToken_EmptyToken(t *testing.T) {
	ms := newTestManagementServer(t, MgmtAPIConfig{})

	body, _ := json.Marshal(map[string]string{"token": ""})
	req := httptest.NewRequest(http.MethodPut, "/identity/token", bytes.NewReader(body))
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestManagementServer_RequireSecret_ValidToken(t *testing.T) {
	ms := newTestManagementServer(t, MgmtAPIConfig{SharedSecret: "s3cret"})

	req := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	if w.Code == http.StatusUnauthorized {
		t.Errorf("valid secret should not return 401")
	}
}

func TestManagementServer_RequireSecret_InvalidToken(t *testing.T) {
	ms := newTestManagementServer(t, MgmtAPIConfig{SharedSecret: "s3cret"})

	tests := []struct {
		name   string
		header string
	}{
		{"wrong secret", "Bearer wrong"},
		{"missing prefix", "s3cret"},
		{"empty header", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/tokens", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			w := httptest.NewRecorder()
			ms.server.Handler.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestManagementServer_UIAlwaysAccessible(t *testing.T) {
	// UI at GET / should be served even when shared secret is configured.
	ms := newTestManagementServer(t, MgmtAPIConfig{SharedSecret: "s3cret"})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No Authorization header.
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	if w.Code == http.StatusUnauthorized {
		t.Error("UI at / should not require auth")
	}
	if w.Code != http.StatusOK {
		t.Errorf("UI status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestManagementServer_AddToken_ManualPostingDisabled(t *testing.T) {
	ms := newTestManagementServer(t, MgmtAPIConfig{}) // AllowManualTokens defaults to false

	raw := makeTestJWT(map[string]any{"jti": "tok-1", "exp": futureExp()})
	body, _ := json.Marshal(map[string]string{"token": raw})
	req := httptest.NewRequest(http.MethodPost, "/tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (manual posting disabled)", w.Code, http.StatusForbidden)
	}
}

func TestManagementServer_UI_HidesManualTokenSection(t *testing.T) {
	ms := newTestManagementServer(t, MgmtAPIConfig{}) // AllowManualTokens: false

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("UI status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "Add Escalation Token") {
		t.Error("UI should not show 'Add Escalation Token' section when AllowManualTokens is false")
	}
}

func TestNewManagementServer_CallbackPageFile_Override(t *testing.T) {
	dir := t.TempDir()
	customHTML := `<!DOCTYPE html><html><body>CUSTOM CALLBACK PAGE {{if .Error}}ERROR{{end}}</body></html>`
	pageFile := filepath.Join(dir, "callback.html")
	if err := os.WriteFile(pageFile, []byte(customHTML), 0600); err != nil {
		t.Fatal(err)
	}

	store, _ := NewTokenStore(context.Background(), filepath.Join(dir, "tokens.json"))
	identity, _ := NewIdentityCache(context.Background(), IdentityConfig{Source: "os", UserID: "test"})
	sm := NewStateMachine()
	oidcLogin := NewOIDCLoginManager(OIDCLoginConfig{IssuerURL: "https://idp.example.com", ClientID: "c"}, DefaultManagementAPIPort, 0, sm, nil, nil, nil)

	ms, err := NewManagementServer(store, identity, MgmtAPIConfig{}, oidcLogin, pageFile)
	if err != nil {
		t.Fatalf("NewManagementServer with custom page file: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("callback status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "CUSTOM CALLBACK PAGE") {
		t.Errorf("response should use custom page file, got: %s", w.Body.String())
	}
}

func TestNewManagementServer_CallbackPageFile_Missing(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewTokenStore(context.Background(), filepath.Join(dir, "tokens.json"))
	identity, _ := NewIdentityCache(context.Background(), IdentityConfig{Source: "os", UserID: "test"})
	sm := NewStateMachine()
	oidcLogin := NewOIDCLoginManager(OIDCLoginConfig{IssuerURL: "https://idp.example.com", ClientID: "c"}, DefaultManagementAPIPort, 0, sm, nil, nil, nil)

	_, err := NewManagementServer(store, identity, MgmtAPIConfig{}, oidcLogin, "/nonexistent/callback.html")
	if err == nil {
		t.Fatal("expected error for missing callback page file, got nil")
	}
}

func TestNewManagementServer_CallbackPageFile_Empty_UsesEmbedded(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewTokenStore(context.Background(), filepath.Join(dir, "tokens.json"))
	identity, _ := NewIdentityCache(context.Background(), IdentityConfig{Source: "os", UserID: "test"})
	sm := NewStateMachine()
	oidcLogin := NewOIDCLoginManager(OIDCLoginConfig{IssuerURL: "https://idp.example.com", ClientID: "c"}, DefaultManagementAPIPort, 0, sm, nil, nil, nil)

	ms, err := NewManagementServer(store, identity, MgmtAPIConfig{}, oidcLogin, "")
	if err != nil {
		t.Fatalf("NewManagementServer with empty page file: %v", err)
	}
	if ms.callbackTmpl == nil {
		t.Error("callbackTmpl should be set when oidcLogin is non-nil")
	}
}

func TestManagementServer_UI_ShowsManualTokenSection(t *testing.T) {
	ms := newTestManagementServer(t, MgmtAPIConfig{AllowManualTokens: true})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	ms.server.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("UI status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Add Escalation Token") {
		t.Error("UI should show 'Add Escalation Token' section when AllowManualTokens is true")
	}
	if !strings.Contains(body, "jwt-input") {
		t.Error("UI should include the jwt-input textarea when AllowManualTokens is true")
	}
}
