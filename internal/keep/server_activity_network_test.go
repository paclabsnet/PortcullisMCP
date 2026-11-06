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
	"path/filepath"
	"testing"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/keep/activitylog"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// TestServerActivityNetwork_HTTPSink verifies that Keep routes activity log entries
// to an HTTP batch sink and that no local log files are created.
func TestServerActivityNetwork_HTTPSink(t *testing.T) {
	t.Parallel()
	var mu struct{ batches [][]byte }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 65536)
		n, _ := r.Body.Read(body)
		mu.batches = append(mu.batches, body[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "activity.log")

	cfg := cfgloader.MCPActivityLogConfig{
		Enabled:    true,
		Sink:       "http",
		BufferSize: 100,
		HTTP: cfgloader.HTTPActivitySinkConfig{
			URL:              srv.URL,
			Encoding:         "json_array",
			BatchSize:        2,
			MaxQueuedBatches: 5,
			FlushIntervalMS:  100,
			TimeoutMS:        2000,
			MaxRetries:       0,
			RetryBackoffMS:   50,
			Auth:             cfgloader.HTTPActivityAuthConfig{Type: "none"},
		},
		File: logFile, // must NOT be created
	}
	cfg.ApplyDefaults()

	al, err := activitylog.New(cfg)
	if err != nil {
		t.Fatalf("activitylog.New: %v", err)
	}

	al.LogRequest(activitylog.RequestEntry{
		SessionID:  "s1",
		TraceID:    "trace-001",
		UserID:     "alice@corp",
		ServerName: "test-mcp",
		ToolName:   "query_customers",
	})
	al.LogResponse(activitylog.ResponseEntry{
		SessionID:  "s1",
		TraceID:    "trace-001",
		UserID:     "alice@corp",
		ServerName: "test-mcp",
		ToolName:   "query_customers",
		Status:     "success",
		DurationMS: 42,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := al.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// Assert mock SIEM received at least one batch with both events.
	if len(mu.batches) == 0 {
		t.Fatal("mock SIEM received no batches")
	}
	var allEvents []map[string]any
	for _, batch := range mu.batches {
		var arr []map[string]any
		if err := json.Unmarshal(batch, &arr); err != nil {
			t.Fatalf("batch is not valid JSON array: %v — body: %q", err, batch)
		}
		allEvents = append(allEvents, arr...)
	}
	if len(allEvents) < 2 {
		t.Errorf("expected at least 2 events, got %d", len(allEvents))
	}
	var hasRequest, hasResponse bool
	for _, ev := range allEvents {
		switch ev["event"] {
		case "mcp_request":
			hasRequest = true
		case "mcp_response":
			hasResponse = true
		}
	}
	if !hasRequest || !hasResponse {
		t.Errorf("missing events: hasRequest=%v hasResponse=%v — events: %v", hasRequest, hasResponse, allEvents)
	}

	// Zero-disk mandate: no log file created on the filesystem.
	if _, err := os.Stat(logFile); !os.IsNotExist(err) {
		t.Errorf("log file must NOT be created for http sink: %v", logFile)
	}
}

// TestServerActivityNetwork_OTLPSink verifies that Keep routes activity log entries
// to an OTLP sink formatted as ExportLogsServiceRequest, with no local files created.
func TestServerActivityNetwork_OTLPSink(t *testing.T) {
	t.Parallel()
	var gotPayload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		_ = dec.Decode(&gotPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "activity.log")

	cfg := cfgloader.MCPActivityLogConfig{
		Enabled:    true,
		Sink:       "otlp",
		BufferSize: 100,
		OTLP: cfgloader.OTLPActivitySinkConfig{
			Endpoint:         srv.URL + "/v1/logs",
			BatchSize:        2,
			MaxQueuedBatches: 5,
			FlushIntervalMS:  100,
			TimeoutMS:        2000,
			MaxRetries:       0,
			RetryBackoffMS:   50,
			Auth:             cfgloader.HTTPActivityAuthConfig{Type: "none"},
		},
		File: logFile,
	}
	cfg.ApplyDefaults()

	al, err := activitylog.New(cfg)
	if err != nil {
		t.Fatalf("activitylog.New: %v", err)
	}

	al.LogRequest(activitylog.RequestEntry{
		SessionID:  "s2",
		TraceID:    "550e8400-e29b-41d4-a716-446655440000",
		UserID:     "bob@corp",
		ToolName:   "update_order",
		ServerName: "orders-mcp",
	})
	al.LogResponse(activitylog.ResponseEntry{
		SessionID:  "s2",
		TraceID:    "550e8400-e29b-41d4-a716-446655440000",
		UserID:     "bob@corp",
		ToolName:   "update_order",
		ServerName: "orders-mcp",
		Status:     "success",
		DurationMS: 10,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := al.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if gotPayload == nil {
		t.Fatal("mock OTel collector received no payload")
	}
	rl, ok := gotPayload["resourceLogs"].([]any)
	if !ok || len(rl) == 0 {
		t.Fatalf("resourceLogs missing or empty")
	}
	sl := rl[0].(map[string]any)["scopeLogs"].([]any)[0].(map[string]any)
	records := sl["logRecords"].([]any)
	if len(records) < 2 {
		t.Errorf("expected at least 2 logRecords, got %d", len(records))
	}

	// Zero-disk mandate.
	if _, err := os.Stat(logFile); !os.IsNotExist(err) {
		t.Errorf("log file must NOT be created for otlp sink: %v", logFile)
	}
}

// TestServerActivityNetwork_ZeroFallback verifies that an unreachable HTTP sink
// does NOT create a local log file. Events are dropped non-blockingly; Keep proceeds.
func TestServerActivityNetwork_ZeroFallback(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "activity.log")

	// Point to a server that immediately refuses connections.
	cfg := cfgloader.MCPActivityLogConfig{
		Enabled:    true,
		Sink:       "http",
		BufferSize: 10,
		HTTP: cfgloader.HTTPActivitySinkConfig{
			URL:              "http://127.0.0.1:19999", // nothing listening here
			Encoding:         "ndjson",
			BatchSize:        1,
			MaxQueuedBatches: 2,
			FlushIntervalMS:  50,
			TimeoutMS:        200,
			MaxRetries:       0,
			RetryBackoffMS:   10,
			Auth:             cfgloader.HTTPActivityAuthConfig{Type: "none"},
		},
		File: logFile,
	}
	cfg.ApplyDefaults()

	al, err := activitylog.New(cfg)
	if err != nil {
		t.Fatalf("activitylog.New should succeed even with unreachable URL: %v", err)
	}

	al.LogRequest(activitylog.RequestEntry{
		SessionID: "s3", TraceID: "t3", UserID: "eve@corp",
		ToolName: "dangerous_tool", ServerName: "risk-mcp",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = al.Shutdown(ctx) // may return error if events are still pending; ignore

	// Zero-disk mandate: no log file must exist.
	if _, err := os.Stat(logFile); !os.IsNotExist(err) {
		t.Errorf("ZERO-DISK VIOLATION: log file was created despite sink: http — %v", logFile)
	}
}
