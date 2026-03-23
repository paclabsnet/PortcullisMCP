package keep

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
			req := shared.EnrichedMCPRequest{
				ServerName: "test-server",
				ToolName:   "test-tool",
				Arguments:  map[string]any{"arg1": "value1"},
				UserIdentity: shared.UserIdentity{
					UserID:      "user@example.com",
					DisplayName: "Test User",
					Groups:      []string{"developers"},
					SourceType:  "oidc",
				},
				SessionID: "session-123",
				RequestID: "request-456",
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

	requests := []shared.EnrichedMCPRequest{
		{ServerName: "s", ToolName: "t", RequestID: "r1"},
		{ServerName: "s", ToolName: "delete_everything", RequestID: "r2",
			UserIdentity: shared.UserIdentity{UserID: "attacker", Groups: []string{"nobody"}}},
	}
	for _, req := range requests {
		resp, err := pdp.Evaluate(context.Background(), req)
		if err != nil {
			t.Errorf("req %s: unexpected error: %v", req.RequestID, err)
		}
		if resp.Decision != "allow" {
			t.Errorf("req %s: decision = %q, want allow", req.RequestID, resp.Decision)
		}
		if resp.RequestID != req.RequestID {
			t.Errorf("req %s: RequestID not echoed, got %q", req.RequestID, resp.RequestID)
		}
	}
}

func TestNewServer_UnknownPDPType(t *testing.T) {
	cfg := Config{
		PDP: PDPConfig{Type: "unknown-pdp"},
	}
	_, err := NewServer(cfg, "")
	if err == nil {
		t.Fatal("expected error for unknown PDP type, got nil")
	}
	if !strings.Contains(err.Error(), "unknown pdp type") {
		t.Errorf("error = %q, want it to mention unknown pdp type", err.Error())
	}
}

func TestOPAClient_Evaluate_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		<-r.Context().Done()
	}))
	defer srv.Close()

	client := NewOPAClient(srv.URL)
	req := shared.EnrichedMCPRequest{
		ServerName: "test-server",
		ToolName:   "test-tool",
		RequestID:  "request-123",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := client.Evaluate(ctx, req)
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
}
