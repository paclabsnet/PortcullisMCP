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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

func TestNewWorkflowHandler_Noop(t *testing.T) {
	cfg := EscalationConfig{Strategy: "noop"}
	handler, err := NewWorkflowHandler(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}

	req := shared.EnrichedMCPRequest{TraceID: "test-123"}
	reqID, err := handler.Submit(context.Background(), NewAuthorizedRequest(req, shared.Principal{}), "test reason")
	if err != nil {
		t.Errorf("noop handler should not error: %v", err)
	}
	if reqID != "" {
		t.Errorf("request ID = %q, want %q", reqID, "")
	}
}

func TestNewWorkflowHandler_UnknownType(t *testing.T) {
	cfg := EscalationConfig{Strategy: "unknown"}
	handler, err := NewWorkflowHandler(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestServiceNowHandler_Submit(t *testing.T) {
	os.Setenv("TEST_SNOW_CREDS", "test-user:test-pass")
	defer os.Unsetenv("TEST_SNOW_CREDS")

	tests := []struct {
		name          string
		statusCode    int
		responseBody  map[string]any
		expectError   bool
		expectedReqID string
	}{
		{
			name:       "successful creation",
			statusCode: http.StatusCreated,
			responseBody: map[string]any{
				"result": map[string]any{
					"sys_id": "sys123",
					"number": "CHG0123456",
				},
			},
			expectedReqID: "CHG0123456",
		},
		{
			name:        "server error",
			statusCode:  http.StatusInternalServerError,
			expectError: true,
		},
		{
			name:       "unexpected status",
			statusCode: http.StatusOK,
			responseBody: map[string]any{
				"result": map[string]any{
					"number": "CHG0123456",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("expected Content-Type: application/json")
				}
				if r.Header.Get("Authorization") == "" {
					t.Errorf("expected Authorization header")
				}

				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}

				w.WriteHeader(tt.statusCode)
				if tt.responseBody != nil {
					_ = json.NewEncoder(w).Encode(tt.responseBody)
				}
			}))
			defer srv.Close()

			host := strings.TrimPrefix(srv.URL, "https://")

			cfg := ServiceNowConfig{
				Instance:      host,
				CredentialEnv: "TEST_SNOW_CREDS",
			}

			handler, err := newServiceNowHandler(cfg)
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			handler.client = srv.Client()

			req := shared.EnrichedMCPRequest{
				ServerName: "test-server",
				ToolName:   "test-tool",
				TraceID:    "req-123",
				SessionID:  "session-456",
			}
			p := shared.Principal{
				UserID:      "user@example.com",
				DisplayName: "Test User",
			}

			reqID, err := handler.Submit(context.Background(), NewAuthorizedRequest(req, p), "test reason")

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if reqID != tt.expectedReqID {
				t.Errorf("request ID = %q, want %q", reqID, tt.expectedReqID)
			}
		})
	}
}

func TestServiceNowHandler_MissingInstance(t *testing.T) {
	cfg := ServiceNowConfig{
		Instance:      "",
		CredentialEnv: "TEST_CREDS",
	}

	_, err := newServiceNowHandler(cfg)
	if err == nil {
		t.Fatal("expected error for missing instance, got nil")
	}
}

func TestServiceNowHandler_MissingCredentials(t *testing.T) {
	cfg := ServiceNowConfig{
		Instance:      "example.service-now.com",
		CredentialEnv: "NONEXISTENT_ENV_VAR",
	}

	_, err := newServiceNowHandler(cfg)
	if err == nil {
		t.Fatal("expected error for missing credentials, got nil")
	}
}

func TestWebhookHandler_Submit(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		responseBody  map[string]any
		expectError   bool
		expectedReqID string
	}{
		{
			name:       "successful webhook with returned request ID",
			statusCode: http.StatusOK,
			responseBody: map[string]any{
				"request_id": "webhook-123",
			},
			expectedReqID: "webhook-123",
		},
		{
			name:          "successful webhook without request ID",
			statusCode:    http.StatusAccepted,
			responseBody:  map[string]any{},
			expectedReqID: "req-123",
		},
		{
			name:        "server error",
			statusCode:  http.StatusInternalServerError,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("expected Content-Type: application/json")
				}
				if r.Header.Get("X-Custom-Header") != "custom-value" {
					t.Errorf("expected custom header to be set")
				}

				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}

				if body["trace_id"] != "req-123" {
					t.Errorf("expected trace_id in payload")
				}
				if body["tool"] != "test-tool" {
					t.Errorf("expected tool in payload")
				}

				w.WriteHeader(tt.statusCode)
				if tt.responseBody != nil {
					_ = json.NewEncoder(w).Encode(tt.responseBody)
				}
			}))
			defer srv.Close()

			cfg := WebhookConfig{
				URL: srv.URL,
				Headers: map[string]string{
					"X-Custom-Header": "custom-value",
				},
			}

			handler, err := newWebhookHandler(cfg)
			if err != nil {
				t.Fatalf("failed to create handler: %v", err)
			}

			req := shared.EnrichedMCPRequest{
				ServerName: "test-server",
				ToolName:   "test-tool",
				Arguments:  map[string]any{"arg1": "value1"},
				TraceID:    "req-123",
				SessionID:  "session-456",
			}
			p := shared.Principal{
				UserID:      "user@example.com",
				DisplayName: "Test User",
				Groups:      []string{"developers"},
				SourceType:  "oidc",
			}

			reqID, err := handler.Submit(context.Background(), NewAuthorizedRequest(req, p), "test reason")

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if reqID != tt.expectedReqID {
				t.Errorf("request ID = %q, want %q", reqID, tt.expectedReqID)
			}
		})
	}
}

func TestWebhookHandler_MissingURL(t *testing.T) {
	cfg := WebhookConfig{URL: ""}
	_, err := newWebhookHandler(cfg)
	if err == nil {
		t.Fatal("expected error for missing URL, got nil")
	}
}
