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

package activitylog

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// bufferSink collects written lines in memory for test assertions.
type bufferSink struct {
	mu    sync.Mutex
	lines []string
}

func (b *bufferSink) Write(line []byte) error {
	b.mu.Lock()
	b.lines = append(b.lines, string(line))
	b.mu.Unlock()
	return nil
}

func (b *bufferSink) Close() error { return nil }

func (b *bufferSink) all() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.lines...)
}

// newTestLogger creates an ActivityLogger backed by an in-memory bufferSink.
func newTestLogger(cfg cfgloader.MCPActivityLogConfig) (*ActivityLogger, *bufferSink) {
	buf := &bufferSink{}
	cfg.ApplyDefaults()
	al := &ActivityLogger{
		cfg:        cfg,
		ch:         make(chan logEntry, cfg.BufferSize),
		stopWorker: make(chan struct{}),
		workerDone: make(chan struct{}),
		sink:       buf,
	}
	go al.worker()
	return al, buf
}

func shutdownNow(t *testing.T, al *ActivityLogger) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := al.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

// parseRecord unmarshals a JSON line into a map for field assertions.
func parseRecord(t *testing.T, line string) map[string]any {
	t.Helper()
	line = strings.TrimSpace(line)
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("parse record %q: %v", line, err)
	}
	return m
}

// TestLogRequest_BasicFields verifies that LogRequest emits a single-line JSON
// record with the expected event type and core fields.
func TestLogRequest_BasicFields(t *testing.T) {
	al, buf := newTestLogger(cfgloader.MCPActivityLogConfig{
		IncludePDPDecision: true,
	})

	al.LogRequest(RequestEntry{
		SessionID:   "sess-1",
		TraceID:     "trace-1",
		UserID:      "alice@corp",
		Agent:       shared.AgentInfo{Name: "claude-code", Version: "1.0"},
		ServerName:  "db-mcp",
		ToolName:    "query",
		Arguments:   map[string]any{"q": "SELECT 1"},
		PDPDecision: "allow",
		PDPReason:   "",
	})

	shutdownNow(t, al)

	lines := buf.all()
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	r := parseRecord(t, lines[0])

	checks := map[string]string{
		"event":        "mcp_request",
		"session_id":   "sess-1",
		"trace_id":     "trace-1",
		"user_id":      "alice@corp",
		"server_name":  "db-mcp",
		"tool_name":    "query",
		"pdp_decision": "allow",
	}
	for k, want := range checks {
		if got, ok := r[k].(string); !ok || got != want {
			t.Errorf("%s = %v, want %q", k, r[k], want)
		}
	}
	if r["timestamp"] == nil {
		t.Error("timestamp missing")
	}
	agent, _ := r["agent"].(map[string]any)
	if agent["name"] != "claude-code" {
		t.Errorf("agent.name = %v, want claude-code", agent["name"])
	}
}

// TestLogResponse_BasicFields verifies that LogResponse emits a correct record.
func TestLogResponse_BasicFields(t *testing.T) {
	al, buf := newTestLogger(cfgloader.MCPActivityLogConfig{})

	al.LogResponse(ResponseEntry{
		TraceID:    "trace-2",
		UserID:     "bob@corp",
		ToolName:   "drop_table",
		DurationMS: 7,
		Status:     "denied",
		Error:      "policy denied",
	})

	shutdownNow(t, al)

	lines := buf.all()
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	r := parseRecord(t, lines[0])

	if r["event"] != "mcp_response" {
		t.Errorf("event = %v, want mcp_response", r["event"])
	}
	if r["status"] != "denied" {
		t.Errorf("status = %v, want denied", r["status"])
	}
	if r["error"] != "policy denied" {
		t.Errorf("error = %v, want 'policy denied'", r["error"])
	}
	if dur, ok := r["duration_ms"].(float64); !ok || dur != 7 {
		t.Errorf("duration_ms = %v, want 7", r["duration_ms"])
	}
}

// TestLogMalformed_Fields verifies that LogMalformed emits a correct record.
func TestLogMalformed_Fields(t *testing.T) {
	al, buf := newTestLogger(cfgloader.MCPActivityLogConfig{})

	al.LogMalformed(MalformedEntry{
		RemoteAddr: "10.0.0.1:5000",
		TraceID:    "",
		Error:      "unexpected EOF",
		RawPreview: `{"server_name": "db"`,
	})

	shutdownNow(t, al)

	lines := buf.all()
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	r := parseRecord(t, lines[0])

	if r["event"] != "mcp_malformed_request" {
		t.Errorf("event = %v, want mcp_malformed_request", r["event"])
	}
	if r["remote_addr"] != "10.0.0.1:5000" {
		t.Errorf("remote_addr = %v, want 10.0.0.1:5000", r["remote_addr"])
	}
}

// TestIncludePDPDecision_False verifies that pdp_decision and pdp_reason are
// omitted from request records when IncludePDPDecision is false.
func TestIncludePDPDecision_False(t *testing.T) {
	al, buf := newTestLogger(cfgloader.MCPActivityLogConfig{
		IncludePDPDecision: false,
	})

	al.LogRequest(RequestEntry{
		TraceID:     "t",
		PDPDecision: "allow",
		PDPReason:   "some reason",
	})

	shutdownNow(t, al)

	lines := buf.all()
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	r := parseRecord(t, lines[0])
	if _, ok := r["pdp_decision"]; ok {
		t.Error("pdp_decision must be omitted when IncludePDPDecision=false")
	}
	if _, ok := r["pdp_reason"]; ok {
		t.Error("pdp_reason must be omitted when IncludePDPDecision=false")
	}
}

// TestIncludePDPDecision_FalseOmitsErrorDecision verifies that pdp_decision and
// pdp_reason are omitted for all decision values, including "error", when
// IncludePDPDecision is false. Response records convey failure via status.
func TestIncludePDPDecision_FalseOmitsErrorDecision(t *testing.T) {
	al, buf := newTestLogger(cfgloader.MCPActivityLogConfig{
		IncludePDPDecision: false,
	})

	al.LogRequest(RequestEntry{
		TraceID:     "t",
		PDPDecision: "error",
		PDPReason:   "PDP timeout",
	})

	shutdownNow(t, al)

	lines := buf.all()
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	r := parseRecord(t, lines[0])
	if _, ok := r["pdp_decision"]; ok {
		t.Error("pdp_decision must be omitted when IncludePDPDecision=false, even for error outcomes")
	}
	if _, ok := r["pdp_reason"]; ok {
		t.Error("pdp_reason must be omitted when IncludePDPDecision=false, even for error outcomes")
	}
}

// TestTruncation_Arguments verifies that oversized arguments are replaced with
// a truncation envelope and that the original byte count is preserved.
func TestTruncation_Arguments(t *testing.T) {
	al, buf := newTestLogger(cfgloader.MCPActivityLogConfig{
		TruncatePayloads: true,
		MaxPayloadBytes:  20,
	})

	bigValue := strings.Repeat("x", 100)
	al.LogRequest(RequestEntry{
		TraceID:   "t",
		ToolName:  "tool",
		Arguments: map[string]any{"key": bigValue},
	})

	shutdownNow(t, al)

	lines := buf.all()
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	r := parseRecord(t, lines[0])

	args, ok := r["arguments"].(map[string]any)
	if !ok {
		t.Fatalf("arguments not a map: %T %v", r["arguments"], r["arguments"])
	}
	if args["_truncated"] != true {
		t.Errorf("_truncated = %v, want true", args["_truncated"])
	}
	bytes, ok := args["_bytes"].(float64)
	if !ok || bytes <= 20 {
		t.Errorf("_bytes = %v, want > 20", args["_bytes"])
	}
	preview, ok := args["preview"].(string)
	if !ok || len(preview) == 0 {
		t.Errorf("preview = %v, want non-empty string", args["preview"])
	}
}

// TestPayloadNotTruncated_WhenUnderLimit verifies that payloads within the limit
// are passed through unchanged.
func TestPayloadNotTruncated_WhenUnderLimit(t *testing.T) {
	al, buf := newTestLogger(cfgloader.MCPActivityLogConfig{
		TruncatePayloads: true,
		MaxPayloadBytes:  4096,
	})

	al.LogRequest(RequestEntry{
		TraceID:   "t",
		Arguments: map[string]any{"q": "SELECT 1"},
	})

	shutdownNow(t, al)

	r := parseRecord(t, buf.all()[0])
	args, ok := r["arguments"].(map[string]any)
	if !ok {
		t.Fatalf("arguments not a map: %v", r["arguments"])
	}
	if _, truncated := args["_truncated"]; truncated {
		t.Error("small payload must not be truncated")
	}
}

// TestShutdown_FlushesBufferedEntries verifies that all entries enqueued before
// Shutdown are written before Shutdown returns.
func TestShutdown_FlushesBufferedEntries(t *testing.T) {
	al, buf := newTestLogger(cfgloader.MCPActivityLogConfig{})

	const n = 50
	for i := 0; i < n; i++ {
		al.LogRequest(RequestEntry{TraceID: "t", ToolName: "tool"})
	}

	shutdownNow(t, al)

	if got := len(buf.all()); got != n {
		t.Errorf("expected %d lines after shutdown, got %d", n, got)
	}
}

// TestShutdown_Idempotent verifies that calling Shutdown multiple times is safe.
func TestShutdown_Idempotent(t *testing.T) {
	al, _ := newTestLogger(cfgloader.MCPActivityLogConfig{})

	ctx := context.Background()
	if err := al.Shutdown(ctx); err != nil {
		t.Errorf("first Shutdown: %v", err)
	}
	if err := al.Shutdown(ctx); err != nil {
		t.Errorf("second Shutdown: %v", err)
	}
}

// TestShutdown_DropsAfterClosed verifies that enqueue calls after Shutdown return
// immediately and do not panic.
func TestShutdown_DropsAfterClosed(t *testing.T) {
	al, _ := newTestLogger(cfgloader.MCPActivityLogConfig{})
	shutdownNow(t, al)

	// These must not block or panic.
	al.LogRequest(RequestEntry{TraceID: "t"})
	al.LogResponse(ResponseEntry{TraceID: "t"})
}

// TestShutdown_ConcurrentProducers verifies that concurrent producers and a
// concurrent Shutdown call do not race or panic.
func TestShutdown_ConcurrentProducers(t *testing.T) {
	al, _ := newTestLogger(cfgloader.MCPActivityLogConfig{BufferSize: 100})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				al.LogRequest(RequestEntry{TraceID: "t"})
			}
		}()
	}

	// Shutdown concurrently with producers — must not panic.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = al.Shutdown(ctx)

	wg.Wait()
}

// TestSingleLineJSON verifies that each record is a single JSON line (no embedded newlines).
func TestSingleLineJSON(t *testing.T) {
	al, buf := newTestLogger(cfgloader.MCPActivityLogConfig{})

	al.LogRequest(RequestEntry{TraceID: "t", ToolName: "multi\nline\ntool"})
	al.LogResponse(ResponseEntry{TraceID: "t", Status: "success"})

	shutdownNow(t, al)

	for i, line := range buf.all() {
		trimmed := strings.TrimSuffix(line, "\n")
		if strings.ContainsRune(trimmed, '\n') {
			t.Errorf("line %d contains embedded newline: %q", i, line)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(trimmed), &m); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}
}

// TestTruncation_HappensBeforeEnqueue verifies that payload truncation is applied
// before the entry is placed on the channel, so queued entries never hold full
// untruncated payloads in memory.
func TestTruncation_HappensBeforeEnqueue(t *testing.T) {
	al := &ActivityLogger{
		cfg: cfgloader.MCPActivityLogConfig{
			TruncatePayloads: true,
			MaxPayloadBytes:  10,
			BufferSize:       1,
		},
		ch: make(chan logEntry, 1),
		// No worker started — we inspect the channel directly.
	}
	al.cfg.ApplyDefaults()

	bigValue := strings.Repeat("x", 200)
	al.LogRequest(RequestEntry{
		TraceID:   "t",
		Arguments: map[string]any{"key": bigValue},
	})

	entry := <-al.ch
	rec, ok := entry.data.(requestRecord)
	if !ok {
		t.Fatalf("queued entry is %T, want requestRecord", entry.data)
	}
	env, ok := rec.Arguments.(truncationEnvelope)
	if !ok {
		t.Fatalf("queued arguments is %T, want truncationEnvelope; full payload leaked into queue", rec.Arguments)
	}
	if !env.Truncated {
		t.Error("truncationEnvelope.Truncated must be true")
	}
}

// TestTruncateUTF8_Boundary verifies that truncateUTF8 never cuts inside a
// multi-byte rune.
func TestTruncateUTF8_Boundary(t *testing.T) {
	// U+00E9 (é) encodes as 2 bytes: 0xC3 0xA9.
	s := strings.Repeat("é", 10) // 20 bytes
	result := truncateUTF8(s, 3)  // 3 bytes: can fit 1 full rune (2 bytes) but not 2
	if !isValidUTF8String(result) {
		t.Errorf("truncateUTF8 produced invalid UTF-8: %q", result)
	}
	if len(result) > 3 {
		t.Errorf("result length %d > limit 3", len(result))
	}
}

func isValidUTF8String(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' {
			return false
		}
	}
	return true
}
