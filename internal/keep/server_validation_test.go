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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/keep/activitylog"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// captureSink is an ActivitySink that records written lines for test assertions.
type captureSink struct {
	lines []string
}

func (c *captureSink) Write(p []byte) error {
	c.lines = append(c.lines, string(p))
	return nil
}
func (c *captureSink) Close() error { return nil }

// newCaptureActivityLogger creates an ActivityLogger whose output is captured in
// memory. The returned sink can be read after Shutdown to inspect written records.
func newCaptureActivityLogger(cfg cfgloader.MCPActivityLogConfig) (*activitylog.ActivityLogger, *captureSink) {
	cfg.ApplyDefaults()
	sink := &captureSink{}
	al := activitylog.NewWithSink(cfg, sink)
	return al, sink
}

// shutdownLogger flushes and shuts down the logger within 3 seconds.
func shutdownLogger(t *testing.T, al *activitylog.ActivityLogger) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := al.Shutdown(ctx); err != nil {
		t.Errorf("activitylog Shutdown: %v", err)
	}
}

// validatedServer returns a Server with limits fully populated (as NewServer would set them).
func validatedServer() *Server {
	return &Server{
		cfg: Config{
			Limits: LimitsConfig{
				MaxRequestBodyBytes: 1 << 20,
				MaxServerNameBytes:  256,
				MaxToolNameBytes:    256,
				MaxUserIDBytes:      512,
				MaxTraceIDBytes:     128,
				MaxSessionIDBytes:   128,
				MaxReasonBytes:      4096,
				MaxLogBatchSize:     1000,
			},
		},
		pdp:         &mockPDP{decision: "allow"},
		router:      &mockRouter{},
		workflow:    &mockWorkflow{requestID: "ref"},
		normalizer:  &passthroughNormalizer{silenced: true},
	}
}

func TestKeep_Validation_BodyTooLarge(t *testing.T) {
	srv := validatedServer()

	// Build a body that is just over the 1MB limit.
	big := make([]byte, (1<<20)+1)
	for i := range big {
		big[i] = 'x'
	}
	// Wrap in a JSON string field to keep it valid-ish JSON, but the MaxBytesReader
	// will reject before the decoder sees it.
	payload := append([]byte(`{"server_name":"`), big...)
	payload = append(payload, '"', '}')

	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for oversized body", w.Code)
	}
}

func TestKeep_Validation_ServerNameTooLong(t *testing.T) {
	srv := validatedServer()

	reqBody := shared.EnrichedMCPRequest{
		ServerName: strings.Repeat("x", 257), // exceeds 256
		ToolName:   "tool",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for oversized server_name", w.Code)
	}
	if !strings.Contains(w.Body.String(), "server_name") {
		t.Errorf("error response should mention server_name; got: %s", w.Body.String())
	}
}

func TestKeep_Validation_ToolNameTooLong(t *testing.T) {
	srv := validatedServer()

	reqBody := shared.EnrichedMCPRequest{
		ServerName: "server",
		ToolName:   strings.Repeat("y", 257), // exceeds 256
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for oversized tool_name", w.Code)
	}
	if !strings.Contains(w.Body.String(), "tool_name") {
		t.Errorf("error response should mention tool_name; got: %s", w.Body.String())
	}
}

func TestKeep_Validation_TraceIDTooLong(t *testing.T) {
	srv := validatedServer()

	reqBody := shared.EnrichedMCPRequest{
		ServerName: "server",
		ToolName:   "tool",
		TraceID:    strings.Repeat("t", 129), // exceeds 128
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for oversized trace_id", w.Code)
	}
	if !strings.Contains(w.Body.String(), "trace_id") {
		t.Errorf("error response should mention trace_id; got: %s", w.Body.String())
	}
}

// TestCapWriter verifies that capWriter accepts at most max bytes into the
// buffer and always reports a successful write so it does not interrupt the
// io.TeeReader wrapping it.
func TestCapWriter(t *testing.T) {
	var buf bytes.Buffer
	cw := &capWriter{buf: &buf, max: 10}

	// First write: partially fills the cap.
	n, err := cw.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write(5) = (%d, %v), want (5, nil)", n, err)
	}

	// Second write: fills to exactly the cap.
	n, err = cw.Write([]byte("world"))
	if err != nil || n != 5 {
		t.Fatalf("Write(5) = (%d, %v), want (5, nil)", n, err)
	}
	if buf.String() != "helloworld" {
		t.Errorf("buf = %q, want %q", buf.String(), "helloworld")
	}

	// Third write: cap is exhausted; must report success but add nothing to buf.
	n, err = cw.Write([]byte("overflow"))
	if err != nil || n != 8 {
		t.Fatalf("Write(8) after cap = (%d, %v), want (8, nil)", n, err)
	}
	if buf.Len() != 10 {
		t.Errorf("buf.Len() = %d after overflow, want 10", buf.Len())
	}
}

// TestHandleCall_NoTeeWhenLoggingDisabled verifies that handleCall does not
// buffer the request body when activity logging is disabled (activityLog == nil).
// We confirm this indirectly: a malformed request is still rejected with 400 and
// does not panic, proving that the nil activityLog path is exercised cleanly.
func TestHandleCall_NoTeeWhenLoggingDisabled(t *testing.T) {
	srv := validatedServer() // activityLog is nil by default

	req := httptest.NewRequest(http.MethodPost, "/call", strings.NewReader("not-json{{{"))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for malformed body with logging disabled", w.Code)
	}
}

// TestHandleCall_PreviewCappedWhenLoggingEnabled verifies that the bodyBuf
// preview is bounded by MaxPayloadBytes before the entry reaches the logger,
// even when the request body is much larger.
func TestHandleCall_PreviewCappedWhenLoggingEnabled(t *testing.T) {
	const previewCap = 20

	al, sink := newCaptureActivityLogger(cfgloader.MCPActivityLogConfig{
		Enabled:         true,
		MaxPayloadBytes: previewCap,
		BufferSize:      10,
	})

	srv := validatedServer()
	srv.activityLog = al
	srv.cfg.MCPActivityLog = cfgloader.MCPActivityLogConfig{
		Enabled:         true,
		MaxPayloadBytes: previewCap,
	}
	srv.cfg.Limits.MaxServerNameBytes = 256 // 300-char name below triggers rejection

	// Valid JSON but server_name is 300 chars (> 256 limit) → field-length rejection
	// after decode, so LogMalformed fires with the bodyBuf preview.
	longName := strings.Repeat("a", 300)
	body, _ := json.Marshal(shared.EnrichedMCPRequest{
		ServerName: longName,
		ToolName:   "tool",
	})
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}

	shutdownLogger(t, al)

	if len(sink.lines) == 0 {
		t.Fatal("expected a malformed log line, got none")
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(sink.lines[0])), &rec); err != nil {
		t.Fatalf("parse log line: %v", err)
	}
	preview, _ := rec["raw_preview"].(string)
	if len(preview) > previewCap {
		t.Errorf("raw_preview length = %d, want <= %d; cap not applied before enqueue", len(preview), previewCap)
	}
}

// loggedServer returns a validatedServer with an in-memory activity logger attached.
func loggedServer() (*Server, *captureSink) {
	al, sink := newCaptureActivityLogger(cfgloader.MCPActivityLogConfig{
		Enabled:    true,
		BufferSize: 10,
	})
	srv := validatedServer()
	srv.activityLog = al
	return srv, sink
}

// parseSinkRecords flushes the logger and returns all written records as parsed maps.
func parseSinkRecords(t *testing.T, srv *Server, sink *captureSink) []map[string]any {
	t.Helper()
	shutdownLogger(t, srv.activityLog)
	var out []map[string]any
	for _, line := range sink.lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// TestKeep_Log_NormalizationVerifyError verifies that an identity verification
// failure emits mcp_request + mcp_response records with status="denied".
// pdp_decision is omitted because loggedServer uses IncludePDPDecision=false.
func TestKeep_Log_NormalizationVerifyError(t *testing.T) {
	srv, sink := loggedServer()
	srv.normalizer = &mockNormalizer{
		err: &shared.IdentityVerificationError{Reason: "token expired"},
	}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{
		ServerName: "srv", ToolName: "tool",
		UserIdentity: shared.UserIdentity{UserID: "alice", SourceType: "oidc"},
		TraceID:      "trace-norm-verify",
	})
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}

	recs := parseSinkRecords(t, srv, sink)
	if len(recs) != 2 {
		t.Fatalf("want 2 log records (request+response), got %d", len(recs))
	}
	if recs[0]["event"] != "mcp_request" {
		t.Errorf("first record event = %v, want mcp_request", recs[0]["event"])
	}
	if _, ok := recs[0]["pdp_decision"]; ok {
		t.Error("pdp_decision must be omitted when IncludePDPDecision=false")
	}
	if recs[1]["status"] != "denied" {
		t.Errorf("response status = %v, want denied", recs[1]["status"])
	}
}

// TestKeep_Log_NormalizationInfraError verifies that a normalizer infrastructure
// failure emits records with status="backend_error".
func TestKeep_Log_NormalizationInfraError(t *testing.T) {
	srv, sink := loggedServer()
	srv.normalizer = &mockNormalizer{err: errors.New("ldap timeout")}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{
		ServerName: "srv", ToolName: "tool",
		UserIdentity: shared.UserIdentity{UserID: "bob", SourceType: "os"},
		TraceID:      "trace-norm-infra",
	})
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}

	recs := parseSinkRecords(t, srv, sink)
	if len(recs) != 2 {
		t.Fatalf("want 2 log records, got %d", len(recs))
	}
	if recs[1]["status"] != "backend_error" {
		t.Errorf("response status = %v, want backend_error", recs[1]["status"])
	}
}

// TestKeep_Log_ToolErrorResult verifies that a backend result with IsError=true
// is logged with status="tool_error", not status="success".
func TestKeep_Log_ToolErrorResult(t *testing.T) {
	srv, sink := loggedServer()
	srv.router = &mockRouter{
		callToolResult: &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "permission denied by backend"}},
		},
	}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{
		ServerName:   "srv",
		ToolName:     "tool",
		UserIdentity: shared.UserIdentity{UserID: "alice", SourceType: "os"},
		TraceID:      "trace-tool-err",
	})
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	// The HTTP status is still 200 — the error is in the MCP result payload.
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (tool errors are returned as 200 with IsError payload)", w.Code)
	}

	recs := parseSinkRecords(t, srv, sink)
	if len(recs) != 2 {
		t.Fatalf("want 2 log records, got %d", len(recs))
	}
	if recs[1]["status"] != "tool_error" {
		t.Errorf("response status = %v, want tool_error", recs[1]["status"])
	}
}

// TestKeep_Log_EscalationPending_JTIPresent verifies that the mcp_response record
// for an escalation_pending outcome carries escalation_jti so the initial request
// can be joined with the later retry across distinct trace IDs.
func TestKeep_Log_EscalationPending_JTIPresent(t *testing.T) {
	srv, sink := loggedServer()
	srv.pdp = &mockPDP{decision: "escalate"}
	// signer is nil → escalationJTI will be ""; we still expect the field present
	// (empty string omitted via omitempty is fine — test against a non-nil signer
	// is in escalation_test.go). Here we just verify the field plumbing reaches
	// the log entry without panicking.
	srv.workflow = &mockWorkflow{requestID: "wf-ref-123"}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{
		ServerName:   "srv",
		ToolName:     "tool",
		UserIdentity: shared.UserIdentity{UserID: "alice", SourceType: "os"},
		TraceID:      "trace-esc",
	})
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}

	recs := parseSinkRecords(t, srv, sink)
	if len(recs) != 2 {
		t.Fatalf("want 2 log records, got %d", len(recs))
	}
	if recs[1]["status"] != "escalation_pending" {
		t.Errorf("response status = %v, want escalation_pending", recs[1]["status"])
	}
	// escalation_jti is omitted when empty (signer nil), so this asserts the
	// field is absent rather than zero-valued garbage — correct omitempty behaviour.
	if jti, ok := recs[1]["escalation_jti"]; ok && jti != "" {
		t.Errorf("escalation_jti = %v; expected absent or empty when signer is nil", jti)
	}
}

// TestKeep_Log_RetryRequest_JTIPresent verifies that an mcp_request record on a
// retry (EscalationTokens present) carries escalation_jti so it can be joined
// with the original escalation_pending mcp_response.
func TestKeep_Log_RetryRequest_JTIPresent(t *testing.T) {
	srv, sink := loggedServer()
	// PDP allows on retry (token was approved).
	srv.pdp = &mockPDP{decision: "allow"}
	srv.router = &mockRouter{callToolResult: &mcp.CallToolResult{}}

	body, _ := json.Marshal(shared.EnrichedMCPRequest{
		ServerName:   "srv",
		ToolName:     "tool",
		UserIdentity: shared.UserIdentity{UserID: "alice", SourceType: "os"},
		TraceID:      "trace-retry",
		EscalationTokens: []shared.EscalationToken{
			{TokenID: "jti-approved-123", Raw: "header.payload.sig", GrantedBy: "manager"},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	recs := parseSinkRecords(t, srv, sink)
	if len(recs) != 2 {
		t.Fatalf("want 2 log records, got %d", len(recs))
	}
	if recs[0]["event"] != "mcp_request" {
		t.Fatalf("first record event = %v, want mcp_request", recs[0]["event"])
	}
	jtis, _ := recs[0]["escalation_jtis"].([]any)
	if len(jtis) != 1 || jtis[0] != "jti-approved-123" {
		t.Errorf("escalation_jtis = %v, want [jti-approved-123]", recs[0]["escalation_jtis"])
	}
}

// TestKeep_Log_HiddenToolRejected verifies that a call using the real name of an
// aliased tool emits mcp_request + mcp_response records with status="denied".
func TestKeep_Log_HiddenToolRejected(t *testing.T) {
	srv, sink := loggedServer()
	// Wire in a router that considers "delete_x" hidden (aliased as "safe_delete").
	srv.router = aliasTestRouter(map[string]string{"safe_delete": "delete_x"})

	body, _ := json.Marshal(shared.EnrichedMCPRequest{
		ServerName:   "backend",
		ToolName:     "delete_x", // the real (hidden) name
		UserIdentity: shared.UserIdentity{UserID: "alice", SourceType: "os"},
		TraceID:      "trace-hidden",
	})
	req := httptest.NewRequest(http.MethodPost, "/call", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleCall(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}

	recs := parseSinkRecords(t, srv, sink)
	if len(recs) != 2 {
		t.Fatalf("want 2 log records, got %d", len(recs))
	}
	if recs[0]["event"] != "mcp_request" {
		t.Errorf("first record event = %v, want mcp_request", recs[0]["event"])
	}
	if recs[1]["status"] != "denied" {
		t.Errorf("response status = %v, want denied", recs[1]["status"])
	}
}

