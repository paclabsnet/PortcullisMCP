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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// ---- /healthz ---------------------------------------------------------------

func TestHandleHealthz(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.handleHealthz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("status = %q, want %q", result["status"], "ok")
	}
}

// ---- /readyz ----------------------------------------------------------------

func TestHandleReadyz_Ready(t *testing.T) {
	signer, err := NewEscalationSigner(SigningConfig{Key: "test-signing-key-32bytes!!!!!!!!"})
	if err != nil {
		t.Fatalf("NewEscalationSigner: %v", err)
	}
	srv := &Server{
		pdp:    &mockPDP{decision: "allow"},
		router: &mockRouter{listToolsResult: []shared.AnnotatedTool{{ServerName: "s"}}},
		signer: signer,
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	srv.handleReadyz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["status"] != "ready" {
		t.Errorf("status = %q, want %q", result["status"], "ready")
	}
	if result["signer_configured"] != true {
		t.Errorf("signer_configured = %v, want true", result["signer_configured"])
	}
}

func TestHandleReadyz_NoSigner(t *testing.T) {
	// Signer is optional — readyz should still return 200 but report false.
	srv := &Server{
		pdp:         &mockPDP{decision: "allow"},
		router:      &mockRouter{},
		signer:      nil,
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	srv.handleReadyz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["signer_configured"] != false {
		t.Errorf("signer_configured = %v, want false", result["signer_configured"])
	}
}

func TestHandleReadyz_RouterError(t *testing.T) {
	srv := &Server{
		pdp:         &mockPDP{decision: "allow"},
		router:      &mockRouter{listToolsError: errors.New("cache miss")},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	srv.handleReadyz(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["status"] != "unavailable" {
		t.Errorf("status = %q, want %q", result["status"], "unavailable")
	}
}

// ---- auth middleware exemption ----------------------------------------------

func TestAuthMiddleware_ExemptsHealthEndpoints(t *testing.T) {
	srv := &Server{cfg: Config{Listen: ListenConfig{Auth: AuthConfig{BearerToken: "secret"}}}}

	for _, path := range []string{"/healthz", "/readyz"} {
		called := false
		handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, path, nil)
		// Deliberately omit Authorization header.
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if !called {
			t.Errorf("path %s: handler should be called without auth (health endpoint)", path)
		}
		if w.Code != http.StatusOK {
			t.Errorf("path %s: status = %d, want 200", path, w.Code)
		}
	}
}

func TestAuthMiddleware_RequiresTokenForOtherPaths(t *testing.T) {
	srv := &Server{cfg: Config{Listen: ListenConfig{Auth: AuthConfig{BearerToken: "secret"}}}}

	called := false
	handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	req := httptest.NewRequest(http.MethodPost, "/authorize", nil)
	// No Authorization header.
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if called {
		t.Error("handler should not be called without token for non-health path")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}
