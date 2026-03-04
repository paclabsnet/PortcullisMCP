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
)

// mockPDP is a test implementation of PolicyDecisionPoint
type mockPDP struct {
	decision string
	reason   string
	err      error
}

func (m *mockPDP) Evaluate(ctx context.Context, req shared.EnrichedMCPRequest) (shared.PDPResponse, error) {
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
	listToolsResult []*mcp.Tool
	listToolsError  error
}

func (m *mockRouter) CallTool(ctx context.Context, serverName, toolName string, args map[string]any) (*mcp.CallToolResult, error) {
	if m.callToolError != nil {
		return nil, m.callToolError
	}
	return m.callToolResult, nil
}

func (m *mockRouter) ListAllTools(ctx context.Context) ([]*mcp.Tool, error) {
	if m.listToolsError != nil {
		return nil, m.listToolsError
	}
	return m.listToolsResult, nil
}

// mockWorkflow is a test implementation of WorkflowHandler
type mockWorkflow struct {
	requestID string
	err       error
}

func (m *mockWorkflow) Submit(ctx context.Context, req shared.EnrichedMCPRequest, pdpReason string) (string, error) {
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
		pending:     make(map[string]shared.EnrichedMCPRequest),
	}

	reqBody := shared.EnrichedMCPRequest{
		ServerName: "test-server",
		ToolName:   "test-tool",
		Arguments:  map[string]any{"arg1": "value1"},
		UserIdentity: shared.UserIdentity{
			UserID: "user@example.com",
		},
		RequestID: "req-123",
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
		pending:     make(map[string]shared.EnrichedMCPRequest),
	}

	reqBody := shared.EnrichedMCPRequest{
		ServerName: "test-server",
		ToolName:   "test-tool",
		RequestID:  "req-123",
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
		pending:     make(map[string]shared.EnrichedMCPRequest),
	}

	reqBody := shared.EnrichedMCPRequest{
		ServerName: "test-server",
		ToolName:   "test-tool",
		RequestID:  "req-123",
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

	if result["workflow_request_id"] != "workflow-123" {
		t.Errorf("workflow_request_id = %q, want %q", result["workflow_request_id"], "workflow-123")
	}

	// Verify the request was added to pending map
	srv.pendingMu.RLock()
	_, exists := srv.pending["req-123"]
	srv.pendingMu.RUnlock()

	if !exists {
		t.Error("expected request to be added to pending map")
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
		pending:     make(map[string]shared.EnrichedMCPRequest),
	}

	reqBody := shared.EnrichedMCPRequest{
		ServerName: "test-server",
		ToolName:   "test-tool",
		RequestID:  "req-123",
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
		pending:     make(map[string]shared.EnrichedMCPRequest),
	}

	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	srv.handleCall(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestServer_HandleListTools(t *testing.T) {
	router := &mockRouter{
		listToolsResult: []*mcp.Tool{
			{
				Name:        "read_file",
				Description: "Read a file",
			},
			{
				Name:        "write_file",
				Description: "Write a file",
			},
		},
	}

	srv := &Server{
		router: router,
	}

	req := httptest.NewRequest(http.MethodPost, "/tools", nil)
	w := httptest.NewRecorder()

	srv.handleListTools(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusOK)
	}

	var result []*mcp.Tool
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("got %d tools, want 2", len(result))
	}
}

func TestServer_HandleLog(t *testing.T) {
	srv := &Server{
		decisionLog: NewDecisionLogger(DecisionLogConfig{Enabled: false}),
	}

	entries := []DecisionLogEntry{
		{
			SessionID:  "session-123",
			RequestID:  "req-123",
			UserID:     "user@example.com",
			ServerName: "test-server",
			ToolName:   "test-tool",
			Decision:   "allow",
			Reason:     "fast-path",
			Source:     "gate",
		},
		{
			SessionID:  "session-456",
			RequestID:  "req-456",
			UserID:     "user2@example.com",
			ServerName: "test-server",
			ToolName:   "test-tool2",
			Decision:   "allow",
			Reason:     "fast-path",
			Source:     "gate",
		},
	}

	body, _ := json.Marshal(entries)
	req := httptest.NewRequest(http.MethodPost, "/log", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.handleLog(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusAccepted)
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
	}

	req := httptest.NewRequest(http.MethodPost, "/log", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	srv.handleLog(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
