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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
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

func (m *mockRouter) Reload(ctx context.Context, backends map[string]BackendConfig) error {
	return nil
}

// mockWorkflow is a test implementation of WorkflowHandler
type mockWorkflow struct {
	requestID string
	err       error
}

func (m *mockWorkflow) Submit(ctx context.Context, req AuthorizedRequest, pdpReason string) (string, error) {
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
				&mcp.TextContent{Text: "operation successful"},
			},
		},
	}

	srv := &Server{
		pdp:         pdp,
		router:      router,
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	reqBody := shared.EnrichedMCPRequest{
		ServerName: "test-server",
		ToolName:   "test-tool",
		Arguments:  map[string]any{"arg1": "value1"},
		UserIdentity: shared.UserIdentity{
			UserID: "user@example.com",
		},
		TraceID:   "req-123",
		SessionID: "session-456",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleCall(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusOK)
	}

	var result mcp.CallToolResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result.Content) == 0 {
		t.Error("expected content in response")
	}
}

func TestServer_HandleCall_Deny(t *testing.T) {
	pdp := &mockPDP{
		decision: "deny",
		reason:   "insufficient permissions",
	}

	srv := &Server{
		pdp:         pdp,
		router:      &mockRouter{},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	reqBody := shared.EnrichedMCPRequest{
		ServerName: "test-server",
		ToolName:   "test-tool",
		TraceID:    "req-123",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleCall(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusForbidden)
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["error"] == nil {
		t.Error("expected error in response")
	}

	errorMsg, ok := result["error"].(string)
	if !ok {
		t.Fatal("expected error to be a string")
	}

	if errorMsg != "insufficient permissions" {
		t.Errorf("error message = %q, want %q", errorMsg, "insufficient permissions")
	}
}

func TestServer_HandleCall_Escalate(t *testing.T) {
	pdp := &mockPDP{
		decision: "escalate",
		reason:   "requires manager approval",
	}

	workflow := &mockWorkflow{
		requestID: "workflow-123",
	}

	srv := &Server{
		pdp:         pdp,
		router:      &mockRouter{},
		workflow:    workflow,
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	reqBody := shared.EnrichedMCPRequest{
		ServerName: "test-server",
		ToolName:   "test-tool",
		TraceID:    "req-123",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleCall(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusAccepted)
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["status"] != "escalation_pending" {
		t.Errorf("status = %q, want %q", result["status"], "escalation_pending")
	}

	if result["workflow_reference"] != "workflow-123" {
		t.Errorf("workflow_reference = %q, want %q", result["workflow_reference"], "workflow-123")
	}

}

func TestServer_HandleCall_Escalate_NoSignerNoWorkflowRef_Returns500(t *testing.T) {
	// When the signer is not configured AND the workflow handler returns no
	// reference (as the URL handler does now), Keep must return 500 rather than
	// a 202 that Gate and the user cannot act on.
	pdp := &mockPDP{decision: "escalate", reason: "needs approval"}
	srv := &Server{
		pdp:         pdp,
		router:      &mockRouter{},
		workflow:    &mockWorkflow{requestID: ""}, // returns empty reference
		// signer intentionally nil
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{ServerName: "s", ToolName: "t", TraceID: "r"})
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500; body: %s", w.Code, w.Body.String())
	}
}

func TestServer_HandleCall_Escalate_NoSignerWithWorkflowRef_Returns202(t *testing.T) {
	// When the signer is not configured but the workflow handler produces a
	// reference (e.g. a ServiceNow ticket URL), the 202 is still actionable.
	pdp := &mockPDP{decision: "escalate", reason: "needs approval"}
	srv := &Server{
		pdp:         pdp,
		router:      &mockRouter{},
		workflow:    &mockWorkflow{requestID: "https://servicenow.example.com/INC123"},
		// signer intentionally nil
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{ServerName: "s", ToolName: "t", TraceID: "r"})
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202; body: %s", w.Code, w.Body.String())
	}
}

func TestServer_HandleCall_Escalate_IncludesJWT(t *testing.T) {
	// When a signer is configured, the 202 body must include both escalation_jti
	// and pending_jwt so Gate can build the approval URL without relying on the
	// workflow_reference field.
	pdp := &mockPDP{decision: "escalate", reason: "requires manager approval"}
	signer, err := NewEscalationSigner(SigningConfig{Key: "test-signing-key-32bytes!!!!!!!!"})
	if err != nil {
		t.Fatalf("NewEscalationSigner: %v", err)
	}

	srv := &Server{
		pdp:         pdp,
		router:      &mockRouter{},
		workflow:    &mockWorkflow{},
		signer:      signer,
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{ServerName: "s", ToolName: "t", TraceID: "r"})
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result["escalation_jti"] == "" {
		t.Error("escalation_jti should be non-empty when signer is configured")
	}
	if result["pending_jwt"] == "" {
		t.Error("pending_jwt should be non-empty when signer is configured")
	}
}

func TestServer_HandleCall_PDPError(t *testing.T) {
	pdp := &mockPDP{
		err: shared.ErrPDPUnavailable,
	}

	srv := &Server{
		pdp:         pdp,
		router:      &mockRouter{},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	reqBody := shared.EnrichedMCPRequest{
		ServerName: "test-server",
		ToolName:   "test-tool",
		TraceID:    "req-123",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleCall(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestServer_HandleCall_InvalidJSON(t *testing.T) {
	srv := &Server{
		pdp:         &mockPDP{},
		router:      &mockRouter{},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	srv.handleCall(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestServer_HandleCall_WrongAPIVersion(t *testing.T) {
	srv := &Server{
		pdp:         &mockPDP{decision: "allow"},
		router:      &mockRouter{callToolResult: &mcp.CallToolResult{}},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	req := shared.EnrichedMCPRequest{
		APIVersion: "99",
		ServerName: "s", ToolName: "t", TraceID: "tr",
		UserIdentity: shared.UserIdentity{UserID: "u", SourceType: "os"},
	}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for unknown api_version", w.Code, http.StatusBadRequest)
	}
}

func TestServer_HandleCall_EmptyAPIVersionAccepted(t *testing.T) {
	srv := &Server{
		pdp:         &mockPDP{decision: "allow"},
		router:      &mockRouter{callToolResult: &mcp.CallToolResult{}},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	// No APIVersion field — backward compat with older Gate versions.
	req := shared.EnrichedMCPRequest{
		ServerName: "s", ToolName: "t", TraceID: "tr",
		UserIdentity: shared.UserIdentity{UserID: "u", SourceType: "os"},
	}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d for missing api_version (backward compat)", w.Code, http.StatusOK)
	}
}

func TestServer_HandleAuthorize_WrongAPIVersion(t *testing.T) {
	srv := &Server{
		pdp:         &mockPDP{decision: "allow"},
		router:      &mockRouter{},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	req := shared.EnrichedMCPRequest{
		APIVersion: "99",
		ServerName: "s", ToolName: "t", TraceID: "tr",
		UserIdentity: shared.UserIdentity{UserID: "u", SourceType: "os"},
	}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleAuthorize(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for unknown api_version", w.Code, http.StatusBadRequest)
	}
}

func TestServer_HandleAuthorize_EmptyAPIVersionAccepted(t *testing.T) {
	srv := &Server{
		pdp:         &mockPDP{decision: "allow"},
		router:      &mockRouter{},
		workflow:    &mockWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	// No APIVersion field — backward compat with older Gate versions.
	req := shared.EnrichedMCPRequest{
		ServerName: "s", ToolName: "t", TraceID: "tr",
		UserIdentity: shared.UserIdentity{UserID: "u", SourceType: "os"},
	}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleAuthorize(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d for missing api_version (backward compat)", w.Code, http.StatusOK)
	}
}

func TestServer_HandleListTools(t *testing.T) {
	router := &mockRouter{
		listToolsResult: []shared.AnnotatedTool{
			{ServerName: "filesystem", Tool: &mcp.Tool{Name: "read_file", Description: "Read a file"}},
			{ServerName: "github", Tool: &mcp.Tool{Name: "list_repos", Description: "List repos"}},
		},
	}

	srv := &Server{
		router:     router,
		normalizer: &passthroughNormalizer{silenced: true},
	}

	req := httptest.NewRequest(http.MethodPost, "/tools", nil)
	w := httptest.NewRecorder()

	srv.handleListTools(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusOK)
	}

	var result []shared.AnnotatedTool
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("got %d tools, want 2", len(result))
	}

	if result[0].ServerName != "filesystem" {
		t.Errorf("tool[0].ServerName = %q, want %q", result[0].ServerName, "filesystem")
	}
	if result[1].ServerName != "github" {
		t.Errorf("tool[1].ServerName = %q, want %q", result[1].ServerName, "github")
	}
}

func TestServer_HandleLog(t *testing.T) {
	srv := &Server{
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	entries := []DecisionLogEntry{
		{
			SessionID:  "session-123",
			TraceID:    "req-123",
			UserID:     "user@example.com",
			ServerName: "test-server",
			ToolName:   "test-tool",
			Decision:   "allow",
			Reason:     "fast-path",
			Source:     "gate",
		},
		{
			SessionID:  "session-456",
			TraceID:    "req-456",
			UserID:     "user2@example.com",
			ServerName: "test-server",
			ToolName:   "test-tool2",
			Decision:   "allow",
			Reason:     "fast-path",
			Source:     "gate",
		},
	}

	body, _ := json.Marshal(struct {
		APIVersion string             `json:"api_version"`
		Entries    []DecisionLogEntry `json:"entries"`
	}{APIVersion: shared.APIVersion, Entries: entries})
	req := httptest.NewRequest(http.MethodPost, "/log", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleLog(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusOK)
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["status"] != "accepted" {
		t.Errorf("status = %q, want %q", result["status"], "accepted")
	}

	count, ok := result["count"].(float64)
	if !ok {
		t.Fatal("expected count to be a number")
	}

	if int(count) != 2 {
		t.Errorf("count = %d, want 2", int(count))
	}
}

func TestServer_HandleLog_InvalidJSON(t *testing.T) {
	srv := &Server{
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	req := httptest.NewRequest(http.MethodPost, "/log", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	srv.handleLog(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestServer_HandleLog_BareArray_Rejected(t *testing.T) {
	// A Gate that pre-dates the versioned envelope posts a raw JSON array.
	// Keep must reject it with 400 — the decoder cannot unmarshal an array
	// into the envelope struct, so the request fails before version checking.
	srv := &Server{
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	entries := []DecisionLogEntry{{Decision: "allow", ToolName: "t", ServerName: "s"}}
	body, _ := json.Marshal(entries) // bare array, no envelope
	req := httptest.NewRequest(http.MethodPost, "/log", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleLog(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for bare array (no envelope)", w.Code)
	}
}

func TestServer_HandleLog_WrongAPIVersion(t *testing.T) {
	srv := &Server{
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	body, _ := json.Marshal(struct {
		APIVersion string             `json:"api_version"`
		Entries    []DecisionLogEntry `json:"entries"`
	}{APIVersion: "99", Entries: []DecisionLogEntry{{Decision: "allow"}}})
	req := httptest.NewRequest(http.MethodPost, "/log", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleLog(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for unknown api_version", w.Code)
	}
}

func TestServer_HandleLog_EmptyAPIVersionAccepted(t *testing.T) {
	srv := &Server{
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	// No api_version field — backward compat with older Gate versions.
	body, _ := json.Marshal(struct {
		Entries []DecisionLogEntry `json:"entries"`
	}{Entries: []DecisionLogEntry{{Decision: "allow", ToolName: "t", ServerName: "s"}}})
	req := httptest.NewRequest(http.MethodPost, "/log", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleLog(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for missing api_version (backward compat)", w.Code)
	}
}

// --- workflow decision tests ---

func TestServer_HandleCall_Workflow_WithHandler_Returns202(t *testing.T) {
	signer, err := NewEscalationSigner(SigningConfig{Key: "test-signing-key-32bytes!!!!!!!!"})
	if err != nil {
		t.Fatalf("NewEscalationSigner: %v", err)
	}
	srv := &Server{
		pdp:         &mockPDP{decision: "workflow", reason: "requires ServiceNow approval"},
		router:      &mockRouter{},
		workflow:    &mockWorkflow{requestID: "SNOW-12345"},
		signer:      signer,
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{ServerName: "s", ToolName: "delete_customer", TraceID: "t1"})
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["status"] != "workflow_pending" {
		t.Errorf("status = %q, want \"workflow_pending\"", result["status"])
	}
	if result["workflow_reference"] != "SNOW-12345" {
		t.Errorf("workflow_reference = %q, want \"SNOW-12345\"", result["workflow_reference"])
	}
	if result["escalation_jti"] == "" {
		t.Error("escalation_jti should be non-empty when signer is configured")
	}
	if result["pending_jwt"] == "" {
		t.Error("pending_jwt should be non-empty when signer is configured")
	}
}

func TestServer_HandleCall_Workflow_NoHandler_Returns403(t *testing.T) {
	// noopWorkflow is what NewWorkflowHandler returns when no type is configured.
	// A "workflow" decision with no real handler must be treated as a deny.
	srv := &Server{
		pdp:         &mockPDP{decision: "workflow", reason: "requires external approval"},
		router:      &mockRouter{},
		workflow:    &noopWorkflow{},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{ServerName: "s", ToolName: "delete_customer", TraceID: "t2"})
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["error"] == "" {
		t.Errorf("expected non-empty error message in deny response, got %v", result)
	}
}

func TestServer_HandleCall_Workflow_HandlerError_Returns500(t *testing.T) {
	srv := &Server{
		pdp:         &mockPDP{decision: "workflow", reason: "requires approval"},
		router:      &mockRouter{},
		workflow:    &mockWorkflow{err: fmt.Errorf("servicenow unavailable")},
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{ServerName: "s", ToolName: "delete_customer", TraceID: "t3"})
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestServer_HandleCall_Workflow_NoSignerNoRef_Returns500(t *testing.T) {
	// No signer and the workflow handler returns an empty reference — no
	// approval artifact exists, so Keep must fail rather than return a false-success 202.
	srv := &Server{
		pdp:         &mockPDP{decision: "workflow", reason: "requires approval"},
		router:      &mockRouter{},
		workflow:    &mockWorkflow{requestID: ""}, // returns empty reference
		// signer intentionally nil
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
		normalizer:  &passthroughNormalizer{silenced: true},
	}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{ServerName: "s", ToolName: "delete_customer", TraceID: "t4"})
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when no pending_jwt and no workflow reference", w.Code)
	}
}
