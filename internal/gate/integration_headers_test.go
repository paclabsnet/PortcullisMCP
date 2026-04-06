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

//go:build integration

package gate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// TestHeaderForwarding_EndToEnd_GateToKeep verifies that ClientHeaders set on
// an EnrichedMCPRequest are correctly serialized and delivered to Keep by the
// Forwarder. It uses a fake Keep server that records the decoded request body.
//
// This covers the Gate→Keep transport leg of header forwarding.
func TestHeaderForwarding_EndToEnd_GateToKeep(t *testing.T) {
	var capturedReq shared.EnrichedMCPRequest

	keepSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/call" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&capturedReq); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		result := mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "ok"}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer keepSrv.Close()

	fwd, err := NewForwarder(cfgloader.PeerAuth{Endpoint: keepSrv.URL})
	if err != nil {
		t.Fatalf("create forwarder: %v", err)
	}

	enriched := shared.EnrichedMCPRequest{
		APIVersion: shared.APIVersion,
		ServerName: "test-backend",
		ToolName:   "some_tool",
		Arguments:  map[string]any{"key": "val"},
		ClientHeaders: map[string][]string{
			"Authorization": {"Bearer integration-token"},
			"X-Tenant-Id":   {"acme-corp"},
		},
		TraceID:   "trace-123",
		SessionID: "sess-456",
	}

	if _, err := fwd.CallTool(context.Background(), enriched); err != nil {
		t.Fatalf("forwarder.CallTool: %v", err)
	}

	if len(capturedReq.ClientHeaders) == 0 {
		t.Fatal("Keep received no ClientHeaders in EnrichedMCPRequest")
	}
	if got := capturedReq.ClientHeaders["Authorization"]; len(got) == 0 || got[0] != "Bearer integration-token" {
		t.Errorf("Authorization: got %v, want [Bearer integration-token]", got)
	}
	if got := capturedReq.ClientHeaders["X-Tenant-Id"]; len(got) == 0 || got[0] != "acme-corp" {
		t.Errorf("X-Tenant-Id: got %v, want [acme-corp]", got)
	}
}

// TestHeaderForwarding_ResourceLimits_Keep verifies that when ClientHeaders
// exceed Keep's enforced limits, Keep rejects the request with 400 Bad Request
// and that the Gate Forwarder surfaces this as an error.
func TestHeaderForwarding_ResourceLimits_Keep(t *testing.T) {
	var capturedReq shared.EnrichedMCPRequest

	// Fake Keep enforces MaxForwardedHeaders = 2.
	keepSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/call" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&capturedReq); err != nil {
			http.Error(w, `{"error":"bad body"}`, http.StatusBadRequest)
			return
		}
		if len(capturedReq.ClientHeaders) > 2 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"too many forwarded headers: 3 exceeds limit of 2"}`))
			return
		}
		result := mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer keepSrv.Close()

	fwd, err := NewForwarder(cfgloader.PeerAuth{Endpoint: keepSrv.URL})
	if err != nil {
		t.Fatalf("create forwarder: %v", err)
	}

	// 3 headers — exceeds the fake limit of 2.
	enriched := shared.EnrichedMCPRequest{
		APIVersion: shared.APIVersion,
		ServerName: "backend",
		ToolName:   "tool",
		Arguments:  map[string]any{},
		ClientHeaders: map[string][]string{
			"Authorization": {"Bearer tok"},
			"X-Tenant-Id":   {"acme"},
			"X-Extra":       {"overflow"},
		},
	}

	_, err = fwd.CallTool(context.Background(), enriched)
	if err == nil {
		t.Error("expected error when ClientHeaders exceed Keep's limit, got nil")
	}

	// Confirm all 3 headers were serialized and transmitted.
	if len(capturedReq.ClientHeaders) != 3 {
		t.Errorf("expected 3 headers in serialized request body, got %d", len(capturedReq.ClientHeaders))
	}
}
