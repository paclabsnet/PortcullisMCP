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
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

func TestOPAClient_Evaluate(t *testing.T) {
	tests := []struct {
		name             string
		opaResponse      map[string]any
		opaStatusCode    int
		expectedDecision string
		expectedReason   string
		expectError      bool
	}{
		{
			name: "allow decision",
			opaResponse: map[string]any{
				"result": map[string]any{
					"decision": "allow",
					"reason":   "user has permissions",
				},
			},
			opaStatusCode:    http.StatusOK,
			expectedDecision: "allow",
			expectedReason:   "user has permissions",
		},
		{
			name: "deny decision",
			opaResponse: map[string]any{
				"result": map[string]any{
					"decision": "deny",
					"reason":   "insufficient permissions",
				},
			},
			opaStatusCode:    http.StatusOK,
			expectedDecision: "deny",
			expectedReason:   "insufficient permissions",
		},
		{
			name: "escalate decision",
			opaResponse: map[string]any{
				"result": map[string]any{
					"decision": "escalate",
					"reason":   "requires manager approval",
				},
			},
			opaStatusCode:    http.StatusOK,
			expectedDecision: "escalate",
			expectedReason:   "requires manager approval",
		},
		{
			name: "missing result field defaults to deny",
			opaResponse: map[string]any{
				"other": "data",
			},
			opaStatusCode:    http.StatusOK,
			expectedDecision: "deny",
			expectedReason:   "",
		},
		{
			name:          "opa server error",
			opaResponse:   nil,
			opaStatusCode: http.StatusInternalServerError,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}

				// Verify request body contains input
				var reqBody map[string]any
				if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
					t.Errorf("failed to decode request body: %v", err)
				}
				if _, ok := reqBody["input"]; !ok {
					t.Errorf("request body missing 'input' field")
				}

				w.WriteHeader(tt.opaStatusCode)
				if tt.opaResponse != nil {
					_ = json.NewEncoder(w).Encode(tt.opaResponse)
				}
			}))
			defer srv.Close()

			client := NewOPAClient(srv.URL)
			req := AuthorizedRequest{
				ServerName: "test-server",
				ToolName:   "test-tool",
				Arguments:  map[string]any{"arg1": "value1"},
				Principal: shared.Principal{
					UserID:      "user@example.com",
					DisplayName: "Test User",
					Groups:      []string{"developers"},
					SourceType:  "oidc",
				},
				SessionID: "session-123",
				TraceID:   "request-456",
			}

			resp, err := client.Evaluate(context.Background(), req)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.Decision != tt.expectedDecision {
				t.Errorf("decision = %q, want %q", resp.Decision, tt.expectedDecision)
			}

			if resp.Reason != tt.expectedReason {
				t.Errorf("reason = %q, want %q", resp.Reason, tt.expectedReason)
			}
		})
	}
}

func TestNoopPDP_AlwaysAllows(t *testing.T) {
	pdp := NewNoopPDPClient()

	requests := []AuthorizedRequest{
		{ServerName: "s", ToolName: "t", TraceID: "r1"},
		{ServerName: "s", ToolName: "delete_everything", TraceID: "r2",
			Principal: shared.Principal{UserID: "attacker", Groups: []string{"nobody"}}},
	}
	for _, req := range requests {
		resp, err := pdp.Evaluate(context.Background(), req)
		if err != nil {
			t.Errorf("req %s: unexpected error: %v", req.TraceID, err)
		}
		if resp.Decision != "allow" {
			t.Errorf("req %s: decision = %q, want allow", req.TraceID, resp.Decision)
		}
	}
}

func TestNewServer_UnknownPDPType(t *testing.T) {
	cfg := Config{
		Responsibility: ResponsibilityConfig{
			Policy: PolicyConfig{Strategy: "unknown-pdp"},
		},
	}
	_, err := NewServer(context.Background(), cfg, "")
	if err == nil {
		t.Fatal("expected error for unknown PDP type, got nil")
	}
	if !strings.Contains(err.Error(), "unknown pdp strategy") {
		t.Errorf("error = %q, want it to mention unknown pdp strategy", err.Error())
	}
}

func TestOPAClient_Evaluate_PropagatesTraceContext(t *testing.T) {
	// Two globals must both be set for header injection to work:
	//
	//   1. TracerProvider — the noop provider (OTel's default) returns spans
	//      with invalid trace IDs, so the propagator has nothing to encode.
	//      We install a real SDK provider so the span below gets a valid,
	//      sampled trace ID.
	//
	//   2. TextMapPropagator — independently defaults to a noop, so even with
	//      a real span the Inject call is a no-op unless we also install the
	//      W3C TraceContext propagator.
	//
	// Both are restored to their noop defaults in t.Cleanup so other tests
	// are not affected.
	tp := sdktrace.NewTracerProvider()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
	})

	var capturedTraceparent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTraceparent = r.Header.Get("Traceparent")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{"decision": "allow"},
		})
	}))
	defer srv.Close()

	ctx, span := otel.Tracer("test").Start(context.Background(), "test-span")
	defer span.End()

	client := NewOPAClient(srv.URL)
	_, err := client.Evaluate(ctx, AuthorizedRequest{
		ServerName: "test-server",
		ToolName:   "test-tool",
		TraceID:    "req-trace-test",
	})
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if capturedTraceparent == "" {
		t.Error("expected Traceparent header to be forwarded to OPA, got empty string")
	}
	if !strings.HasPrefix(capturedTraceparent, "00-") {
		t.Errorf("Traceparent header %q does not look like a valid W3C traceparent", capturedTraceparent)
	}
}

func TestOPAClient_Evaluate_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		<-r.Context().Done()
	}))
	defer srv.Close()

	client := NewOPAClient(srv.URL)
	req := AuthorizedRequest{
		ServerName: "test-server",
		ToolName:   "test-tool",
		TraceID:    "request-123",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := client.Evaluate(ctx, req)
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
}
