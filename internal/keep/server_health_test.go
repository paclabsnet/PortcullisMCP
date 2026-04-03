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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

func TestHealthz(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	srv.handleHealthz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status=ok, got %q", resp["status"])
	}
}

func TestReadyz_Ready(t *testing.T) {
	srv := &Server{
		router: &mockRouter{},
	}
	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()

	srv.handleReadyz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ready" {
		t.Errorf("expected status=ready, got %v", resp["status"])
	}
}

func TestReadyz_NotReady(t *testing.T) {
	srv := &Server{
		router: &mockRouter{listToolsError: fmt.Errorf("router not ready")},
	}
	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()

	srv.handleReadyz(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "unavailable" {
		t.Errorf("expected status=unavailable, got %v", resp["status"])
	}
}

func TestAuthMiddleware_ExemptHealth(t *testing.T) {
	cfg := Config{
		Server: cfgloader.ServerConfig{
			Endpoints: map[string]cfgloader.EndpointConfig{
				"main": {
					Auth: cfgloader.AuthSettings{
						Credentials: cfgloader.AuthCredentials{
							BearerToken: "secret",
						},
					},
				},
			},
		},
	}
	srv := &Server{
		cfg:         cfg,
		decisionLog: NewDecisionLogger(cfgloader.DecisionLogConfig{Enabled: false}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", srv.handleHealthz)
	handler := srv.authMiddleware(mux)

	// healthz should pass without token
	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("healthz: expected 200, got %d", w.Code)
	}

	// other endpoint should fail without token
	mux.HandleFunc("POST /call", srv.handleCall)
	req = httptest.NewRequest("POST", "/call", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("call: expected 401, got %d", w.Code)
	}
}
