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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

func defaultOTLPSinkCfg(endpoint string) cfgloader.OTLPActivitySinkConfig {
	return cfgloader.OTLPActivitySinkConfig{
		Endpoint:         endpoint,
		BatchSize:        3,
		MaxQueuedBatches: 2,
		FlushIntervalMS:  200,
		TimeoutMS:        2000,
		MaxRetries:       1,
		RetryBackoffMS:   50,
		Auth:             cfgloader.HTTPActivityAuthConfig{Type: "none"},
	}
}

func TestOTLPSink_Serialization(t *testing.T) {
	t.Parallel()
	var gotPayload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type: got %q, want application/json", r.Header.Get("Content-Type"))
		}
		dec := json.NewDecoder(r.Body)
		_ = dec.Decode(&gotPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	entry := `{"timestamp":"2026-11-03T20:15:30.123456789Z","event":"mcp_request","trace_id":"550e8400-e29b-41d4-a716-446655440000","user_id":"alice@corp","tool_name":"query_customers","server_name":"db-mcp","agent":{"name":"claude","version":"3.0"}}`
	cfg := defaultOTLPSinkCfg(srv.URL)
	sink, err := NewOTLPSink(cfg)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	_ = sink.Write([]byte(entry))
	_ = sink.Write([]byte(`{"event":"mcp_response","status":"success","duration_ms":42}`))
	_ = sink.Write([]byte(`{"event":"mcp_response","status":"denied"}`)) // triggers batch
	time.Sleep(400 * time.Millisecond)
	_ = sink.Close()

	if gotPayload == nil {
		t.Fatal("no payload received by mock OTel collector")
	}

	// Validate top-level structure.
	rl, ok := gotPayload["resourceLogs"].([]any)
	if !ok || len(rl) != 1 {
		t.Fatalf("resourceLogs: got %T len=%d", gotPayload["resourceLogs"], len(rl))
	}
	resourceLog := rl[0].(map[string]any)

	// resource.attributes must include service.name
	res := resourceLog["resource"].(map[string]any)
	attrs := res["attributes"].([]any)
	found := false
	for _, a := range attrs {
		attr := a.(map[string]any)
		if attr["key"] == "service.name" {
			val := attr["value"].(map[string]any)
			if val["stringValue"] == "portcullis-keep" {
				found = true
			}
		}
	}
	if !found {
		t.Error("resource.attributes missing service.name=portcullis-keep")
	}

	// scope.name
	sl := resourceLog["scopeLogs"].([]any)[0].(map[string]any)
	scope := sl["scope"].(map[string]any)
	if scope["name"] != "portcullis.activity_log" {
		t.Errorf("scope.name: %v", scope["name"])
	}

	// logRecords
	records := sl["logRecords"].([]any)
	if len(records) != 3 {
		t.Fatalf("want 3 logRecords, got %d", len(records))
	}

	// First record (mcp_request with trace_id UUID)
	rec0 := records[0].(map[string]any)

	// traceId must be 32-char hex (UUID hyphens stripped)
	traceID, hasTraceID := rec0["traceId"].(string)
	if !hasTraceID || traceID != "550e8400e29b41d4a716446655440000" {
		t.Errorf("traceId: got %q, want 550e8400e29b41d4a716446655440000", traceID)
	}

	// severityNumber for mcp_request = 9 (INFO)
	sevNum := rec0["severityNumber"].(float64)
	if sevNum != 9 {
		t.Errorf("severityNumber: got %v, want 9", sevNum)
	}
	if rec0["severityText"] != "INFO" {
		t.Errorf("severityText: got %v", rec0["severityText"])
	}

	// timeUnixNano must be non-empty
	if rec0["timeUnixNano"] == "" {
		t.Error("timeUnixNano is empty")
	}

	// body stringValue contains the original entry
	body := rec0["body"].(map[string]any)
	sv := body["stringValue"].(string)
	if sv != entry {
		t.Errorf("body.stringValue: got %q, want %q", sv, entry)
	}

	// attributes must include event.type, mcp.tool_name, user.id, mcp.agent.name
	recAttrs := rec0["attributes"].([]any)
	attrMap := map[string]string{}
	for _, a := range recAttrs {
		attr := a.(map[string]any)
		key := attr["key"].(string)
		val := attr["value"].(map[string]any)
		if sv, ok := val["stringValue"].(string); ok {
			attrMap[key] = sv
		}
	}
	checks := map[string]string{
		"event.type":      "mcp_request",
		"mcp.tool_name":   "query_customers",
		"mcp.server_name": "db-mcp",
		"user.id":         "alice@corp",
		"mcp.agent.name":  "claude",
	}
	for k, want := range checks {
		if got := attrMap[k]; got != want {
			t.Errorf("attribute %s: got %q, want %q", k, got, want)
		}
	}

	// Third record (denied) should be WARN (13)
	rec2 := records[2].(map[string]any)
	if rec2["severityNumber"].(float64) != 13 {
		t.Errorf("denied record severityNumber: got %v, want 13", rec2["severityNumber"])
	}
}

func TestOTLPSink_NonHexTraceID(t *testing.T) {
	t.Parallel()
	var gotPayload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		_ = dec.Decode(&gotPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := defaultOTLPSinkCfg(srv.URL)
	sink, err := NewOTLPSink(cfg)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	// Non-hex trace_id: should be absent from traceId field, present in attributes.
	entry := `{"event":"mcp_request","trace_id":"test-trace-123"}`
	_ = sink.Write([]byte(entry))
	_ = sink.Write([]byte(`{"event":"mcp_response","status":"success"}`))
	_ = sink.Write([]byte(`{"event":"mcp_response","status":"denied"}`))
	time.Sleep(400 * time.Millisecond)
	_ = sink.Close()

	if gotPayload == nil {
		t.Fatal("no payload received")
	}
	rl := gotPayload["resourceLogs"].([]any)[0].(map[string]any)
	sl := rl["scopeLogs"].([]any)[0].(map[string]any)
	rec0 := sl["logRecords"].([]any)[0].(map[string]any)

	// traceId must be absent (not a valid 32-hex string)
	if _, hasTraceID := rec0["traceId"]; hasTraceID {
		t.Errorf("traceId should be absent for non-hex trace_id, got %v", rec0["traceId"])
	}

	// mcp.trace_id attribute must be present with original value
	attrs := rec0["attributes"].([]any)
	found := false
	for _, a := range attrs {
		attr := a.(map[string]any)
		if attr["key"] == "mcp.trace_id" {
			val := attr["value"].(map[string]any)
			if val["stringValue"] == "test-trace-123" {
				found = true
			}
		}
	}
	if !found {
		t.Error("mcp.trace_id attribute not found for non-hex trace_id")
	}
}

func TestOTLPSink_MockCollector(t *testing.T) {
	t.Parallel()
	var gotBody []byte
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody = make([]byte, 65536)
		n, _ := r.Body.Read(gotBody)
		gotBody = gotBody[:n]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := defaultOTLPSinkCfg(srv.URL + "/v1/logs")
	cfg.Auth = cfgloader.HTTPActivityAuthConfig{Type: "bearer", Token: "otel-token-xyz"}
	cfg.Headers = map[string]string{"X-Dataset": "portcullis"}
	sink, err := NewOTLPSink(cfg)
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	_ = sink.Write([]byte(`{"event":"mcp_request","tool_name":"my_tool"}`))
	_ = sink.Write([]byte(`{"event":"mcp_response","status":"success"}`))
	_ = sink.Write([]byte(`{"event":"mcp_response","status":"success"}`))
	time.Sleep(400 * time.Millisecond)
	_ = sink.Close()

	if gotPath != "/v1/logs" {
		t.Errorf("path: got %q, want /v1/logs", gotPath)
	}
	var payload map[string]any
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("invalid OTLP JSON: %v — body: %q", err, gotBody)
	}
	if payload["resourceLogs"] == nil {
		t.Error("resourceLogs missing")
	}
}

func TestFormatTraceID(t *testing.T) {
	tests := []struct {
		input    string
		wantHex  string
		wantFall string
	}{
		{
			input:   "550e8400-e29b-41d4-a716-446655440000",
			wantHex: "550e8400e29b41d4a716446655440000",
		},
		{
			input:   "4bf92f3577b34da6a3ce929d0e0e4736",
			wantHex: "4bf92f3577b34da6a3ce929d0e0e4736",
		},
		{
			input:    "test-trace-123",
			wantFall: "test-trace-123",
		},
		{
			input:    "short",
			wantFall: "short",
		},
		{
			input: "",
		},
	}
	for _, tc := range tests {
		got, fall := formatTraceID(tc.input)
		if got != tc.wantHex {
			t.Errorf("formatTraceID(%q) hex = %q, want %q", tc.input, got, tc.wantHex)
		}
		if fall != tc.wantFall {
			t.Errorf("formatTraceID(%q) fallback = %q, want %q", tc.input, fall, tc.wantFall)
		}
	}
}
