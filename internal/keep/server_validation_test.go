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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

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
		decisionLog: NewDecisionLogger(cfgloader.DecisionLogConfig{Enabled: false}),
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

func logBatch(entries []DecisionLogEntry) []byte {
	b, _ := json.Marshal(struct {
		APIVersion string             `json:"api_version"`
		Entries    []DecisionLogEntry `json:"entries"`
	}{APIVersion: "1", Entries: entries})
	return b
}

func TestKeep_Validation_Log_BatchTooLarge(t *testing.T) {
	srv := validatedServer()

	// Build a batch of 1001 entries (exceeds MaxLogBatchSize of 1000).
	entries := make([]DecisionLogEntry, 1001)
	for i := range entries {
		entries[i] = DecisionLogEntry{
			UserID:     "user@example.com",
			ToolName:   "tool",
			ServerName: "server",
			Decision:   "allow",
		}
	}
	body := logBatch(entries)
	req := httptest.NewRequest(http.MethodPost, "/log", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleLog(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for oversized log batch", w.Code)
	}
	if !strings.Contains(w.Body.String(), "maximum") {
		t.Errorf("error response should mention maximum; got: %s", w.Body.String())
	}
}

func TestKeep_Validation_Log_InvalidDecision_Skipped(t *testing.T) {
	srv := validatedServer()

	// One entry with a bad decision, one valid entry.
	entries := []DecisionLogEntry{
		{
			UserID:     "user@example.com",
			ToolName:   "tool",
			ServerName: "server",
			Decision:   "badvalue", // invalid
		},
		{
			UserID:     "user2@example.com",
			ToolName:   "tool2",
			ServerName: "server",
			Decision:   "allow", // valid
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/log", bytes.NewReader(logBatch(entries)))
	w := httptest.NewRecorder()
	srv.handleLog(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 — invalid entries should be skipped, not rejected", w.Code)
	}
	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Only the valid entry should be counted.
	if count, ok := result["count"].(float64); !ok || int(count) != 1 {
		t.Errorf("count = %v, want 1 (invalid entry skipped)", result["count"])
	}
}

func TestKeep_Validation_Log_ReasonTooLong_Skipped(t *testing.T) {
	srv := validatedServer()

	// One entry with an oversized reason, one valid entry.
	entries := []DecisionLogEntry{
		{
			UserID:     "user@example.com",
			ToolName:   "tool",
			ServerName: "server",
			Decision:   "allow",
			Reason:     strings.Repeat("r", 4097), // exceeds 4096
		},
		{
			UserID:     "user2@example.com",
			ToolName:   "tool2",
			ServerName: "server",
			Decision:   "deny",
			Reason:     "normal reason",
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/log", bytes.NewReader(logBatch(entries)))
	w := httptest.NewRecorder()
	srv.handleLog(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 — oversized entries should be skipped, not rejected", w.Code)
	}
	var result map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// Only the valid entry should be counted.
	if count, ok := result["count"].(float64); !ok || int(count) != 1 {
		t.Errorf("count = %v, want 1 (oversized entry skipped)", result["count"])
	}
}
