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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

func TestAuthMiddleware_ValidToken(t *testing.T) {
	cfg := Config{
		Listen: ListenConfig{
			Auth: AuthConfig{
				BearerToken: "test-secret-token",
			},
		},
	}

	srv := &Server{
		cfg:         cfg,
		pdp:         &mockPDP{decision: "allow", reason: "test"},
		router:      &mockRouter{},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &strictNormalizer{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /call", srv.handleCall)
	handler := srv.authMiddleware(mux)

	reqBody := shared.EnrichedMCPRequest{
		ServerName: "test",
		ToolName:   "test-tool",
		TraceID:  "req-123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-secret-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code == http.StatusUnauthorized {
		t.Errorf("expected request to pass auth, got status %d", w.Code)
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	cfg := Config{
		Listen: ListenConfig{
			Auth: AuthConfig{
				BearerToken: "test-secret-token",
			},
		},
	}

	srv := &Server{
		cfg:         cfg,
		pdp:         &mockPDP{decision: "allow", reason: "test"},
		router:      &mockRouter{},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &strictNormalizer{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /call", srv.handleCall)
	handler := srv.authMiddleware(mux)

	reqBody := shared.EnrichedMCPRequest{
		ServerName: "test",
		ToolName:   "test-tool",
		TraceID:  "req-123",
	}
	body, _ := json.Marshal(reqBody)

	tests := []struct {
		name   string
		header string
	}{
		{
			name:   "wrong token",
			header: "Bearer wrong-token",
		},
		{
			name:   "missing bearer prefix",
			header: "test-secret-token",
		},
		{
			name:   "missing authorization header",
			header: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
			}

			var result map[string]string
			if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if result["error"] == "" {
				t.Error("expected error message in response")
			}
		})
	}
}

func TestAuthMiddleware_Disabled(t *testing.T) {
	cfg := Config{
		Listen: ListenConfig{
			Auth: AuthConfig{
				BearerToken: "", // Empty = auth disabled
			},
		},
	}

	srv := &Server{
		cfg:         cfg,
		pdp:         &mockPDP{decision: "allow", reason: "test"},
		router:      &mockRouter{},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &strictNormalizer{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /call", srv.handleCall)

	// When bearer_token is empty, authMiddleware should not be applied
	// So we test directly with mux, not wrapped
	reqBody := shared.EnrichedMCPRequest{
		ServerName: "test",
		ToolName:   "test-tool",
		TraceID:  "req-123",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	// No Authorization header
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	// Should not return 401 when auth is disabled
	if w.Code == http.StatusUnauthorized {
		t.Error("request should pass when bearer auth is disabled")
	}
}
