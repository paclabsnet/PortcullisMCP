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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// ---- handleAuthorize --------------------------------------------------------

func TestServer_HandleAuthorize_Allow(t *testing.T) {
	srv := &Server{
		pdp:         &mockPDP{decision: "allow", reason: "permitted"},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{
		ServerName: "test-server",
		ToolName:   "test-tool",
		TraceID:    "trace-1",
		UserIdentity: shared.UserIdentity{UserID: "user@example.com"},
	})
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleAuthorize(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var result shared.PDPResponse
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Decision != "allow" {
		t.Errorf("decision = %q, want %q", result.Decision, "allow")
	}
}

func TestServer_HandleAuthorize_Deny(t *testing.T) {
	srv := &Server{
		pdp:         &mockPDP{decision: "deny", reason: "not permitted"},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{
		ServerName: "s", ToolName: "t", TraceID: "r",
	})
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleAuthorize(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestServer_HandleAuthorize_Escalate_WithSigner(t *testing.T) {
	signer, err := NewEscalationSigner(SigningConfig{Key: "test-signing-key-32bytes!!!!!!!!"})
	if err != nil {
		t.Fatalf("NewEscalationSigner: %v", err)
	}
	srv := &Server{
		pdp:         &mockPDP{decision: "escalate", reason: "needs approval"},
		workflow:    &mockWorkflow{requestID: "wf-ref"},
		signer:      signer,
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{
		ServerName: "s", ToolName: "t", TraceID: "r",
	})
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleAuthorize(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202; body: %s", w.Code, w.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["escalation_jwt"] == "" {
		t.Error("escalation_jwt should be non-empty when signer is configured")
	}
	if result["escalation_jti"] == "" {
		t.Error("escalation_jti should be non-empty when signer is configured")
	}
}

func TestServer_HandleAuthorize_PDPError(t *testing.T) {
	srv := &Server{
		pdp:         &mockPDP{err: shared.ErrPDPUnavailable},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{
		ServerName: "s", ToolName: "t", TraceID: "r",
	})
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleAuthorize(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestServer_HandleAuthorize_InvalidJSON(t *testing.T) {
	srv := &Server{
		pdp:         &mockPDP{},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader([]byte("not-json")))
	w := httptest.NewRecorder()
	srv.handleAuthorize(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---- adminAuthMiddleware ----------------------------------------------------

func TestAdminAuthMiddleware_NoTokenConfigured_Rejects(t *testing.T) {
	// When no admin token is configured, all requests must be rejected.
	srv := &Server{cfg: Config{Admin: AdminConfig{Token: ""}}}
	called := false
	handler := srv.adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/reload", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if called {
		t.Error("handler should not be called when admin token is not configured")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestAdminAuthMiddleware_WrongToken_Rejects(t *testing.T) {
	srv := &Server{cfg: Config{Admin: AdminConfig{Token: "correct-secret"}}}
	called := false
	handler := srv.adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/reload", nil)
	req.Header.Set("X-Api-Key", "wrong-secret")
	w := httptest.NewRecorder()
	handler(w, req)

	if called {
		t.Error("handler should not be called with wrong token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAdminAuthMiddleware_CorrectToken_Passes(t *testing.T) {
	srv := &Server{cfg: Config{Admin: AdminConfig{Token: "correct-secret"}}}
	called := false
	handler := srv.adminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/reload", nil)
	req.Header.Set("X-Api-Key", "correct-secret")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("handler should be called with correct token")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ---- handleReload -----------------------------------------------------------

// mockReloadRouter allows injecting a Reload error.
type mockReloadRouter struct {
	mockRouter
	reloadErr error
}

func (m *mockReloadRouter) Reload(_ context.Context, _ map[string]BackendConfig) error {
	return m.reloadErr
}

func TestServer_HandleReload_Success(t *testing.T) {
	// Write a minimal valid keep config to a temp file so LoadConfig succeeds.
	cfgContent := `
listen:
  address: "localhost:8080"
pdp:
  endpoint: "http://opa:8181"
`
	tmp := filepath.Join(t.TempDir(), "keep.yaml")
	if err := os.WriteFile(tmp, []byte(cfgContent), 0644); err != nil {
		t.Fatal(err)
	}

	srv := &Server{
		cfg:        Config{Admin: AdminConfig{Token: "secret"}},
		router:     &mockReloadRouter{},
		configPath: tmp,
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/reload", nil)
	req.Header.Set("X-Api-Key", "secret")
	w := httptest.NewRecorder()
	srv.handleReload(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["status"] != "reloaded" {
		t.Errorf("status = %q, want %q", result["status"], "reloaded")
	}
}

func TestServer_HandleReload_BadConfigFile(t *testing.T) {
	srv := &Server{
		router:     &mockReloadRouter{},
		configPath: "/nonexistent/path/keep.yaml",
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/reload", nil)
	w := httptest.NewRecorder()
	srv.handleReload(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}
