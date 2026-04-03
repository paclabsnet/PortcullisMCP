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
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// mockPDP is a test implementation of PolicyDecisionPoint
type mockPDP struct {
	decision string
	reason   string
	err      error
}

func (m *mockPDP) Evaluate(ctx context.Context, req AuthorizedRequest) (shared.PDPResponse, error) {
	if m.err != nil {
		return shared.PDPResponse{}, m.err
	}
	return shared.PDPResponse{
		Decision: m.decision,
		Reason:   m.reason,
	}, nil
}

// mockRouter is a test implementation of the router
type mockRouter struct {
	callToolResult  *mcp.CallToolResult
	callToolError   error
	listToolsResult []shared.AnnotatedTool
	listToolsError  error
}

func (m *mockRouter) CallTool(ctx context.Context, serverName, toolName string, args map[string]any) (*mcp.CallToolResult, error) {
	if m.callToolError != nil {
		return nil, m.callToolError
	}
	return m.callToolResult, nil
}

func (m *mockRouter) ListAllTools(ctx context.Context) ([]shared.AnnotatedTool, error) {
	if m.listToolsError != nil {
		return nil, m.listToolsError
	}
	return m.listToolsResult, nil
}

func (m *mockRouter) Reload(ctx context.Context, backends []BackendConfig) error {
	return nil
}

// mockWorkflow is a test implementation of WorkflowHandler
type mockWorkflow struct {
	requestID string
	err       error
}

func (m *mockWorkflow) Submit(ctx context.Context, req AuthorizedRequest, pendingJWT string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.requestID, nil
}

func TestServer_HandleCall_Allow(t *testing.T) {
	pdp := &mockPDP{
		decision: "allow",
		reason:   "user has permission",
	}

	router := &mockRouter{
		callToolResult: &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: "operation successful",
				},
			},
		},
	}

	cfg := validBaseConfig()
	srv := &Server{
		cfg:         cfg,
		pdp:         pdp,
		router:      router,
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(cfgloader.DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	reqBody := shared.EnrichedMCPRequest{
		APIVersion: shared.APIVersion,
		ServerName: "test-server",
		ToolName:   "test-tool",
		TraceID:    "trace-123",
		UserIdentity: shared.UserIdentity{
			UserID: "user-123",
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleCall(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	var result mcp.CallToolResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}
	if txt, ok := result.Content[0].(*mcp.TextContent); !ok || txt.Text != "operation successful" {
		t.Errorf("unexpected content: %v", result.Content[0])
	}
}

func TestServer_HandleCall_Deny(t *testing.T) {
	pdp := &mockPDP{
		decision: "deny",
		reason:   "policy violation",
	}

	cfg := validBaseConfig()
	srv := &Server{
		cfg:         cfg,
		pdp:         pdp,
		router:      &mockRouter{},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(cfgloader.DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	reqBody := shared.EnrichedMCPRequest{
		APIVersion: shared.APIVersion,
		ServerName: "test-server",
		ToolName:   "test-tool",
		TraceID:    "trace-123",
		UserIdentity: shared.UserIdentity{
			UserID: "user-123",
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleCall(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}

	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["error"] != "policy violation" {
		t.Errorf("expected error %q, got %q", "policy violation", result["error"])
	}
	if result["trace_id"] != "trace-123" {
		t.Errorf("expected trace_id %q, got %q", "trace-123", result["trace_id"])
	}
}

func TestServer_HandleCall_Escalate(t *testing.T) {
	pdp := &mockPDP{
		decision: "escalate",
		reason:   "high-risk operation",
	}

	workflow := &mockWorkflow{
		requestID: "wf-123",
	}

	cfg := validBaseConfig()
	srv := &Server{
		cfg:         cfg,
		pdp:         pdp,
		router:      &mockRouter{},
		workflow:    workflow,
		decisionLog: NewDecisionLogger(cfgloader.DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	reqBody := shared.EnrichedMCPRequest{
		APIVersion: shared.APIVersion,
		ServerName: "test-server",
		ToolName:   "test-tool",
		TraceID:    "trace-123",
		UserIdentity: shared.UserIdentity{
			UserID: "user-123",
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleCall(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected status 202, got %d", w.Code)
	}

	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["status"] != "escalation_pending" {
		t.Errorf("expected status %q, got %q", "escalation_pending", result["status"])
	}
	if result["workflow_reference"] != "wf-123" {
		t.Errorf("expected workflow_reference %q, got %q", "wf-123", result["workflow_reference"])
	}
}
