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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRouter_CallTool_UnknownBackend(t *testing.T) {
	cfg := []BackendConfig{}
	router := NewRouter(cfg)

	_, err := router.CallTool(context.Background(), "nonexistent", "tool", nil)
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}

	expectedMsg := "unknown backend"
	if err.Error()[:len(expectedMsg)] != expectedMsg {
		t.Errorf("error message = %q, want prefix %q", err.Error(), expectedMsg)
	}
}

func TestRouter_BuildBackendTransport_Stdio(t *testing.T) {
	cfg := BackendConfig{
		Type:    "stdio",
		Command: "echo",
		Args:    []string{"hello"},
		Env: map[string]string{
			"TEST_VAR": "test-value",
		},
	}

	transport, err := buildBackendTransport(&backendConn{cfg: cfg})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
}

func TestRouter_BuildBackendTransport_StdioMissingCommand(t *testing.T) {
	cfg := BackendConfig{
		Type: "stdio",
		// Command is missing
	}

	_, err := buildBackendTransport(&backendConn{cfg: cfg})
	if err == nil {
		t.Fatal("expected error for stdio backend without command, got nil")
	}

	expectedMsg := "requires a command"
	if err.Error()[len(err.Error())-len(expectedMsg):] != expectedMsg {
		t.Errorf("error message = %q, want suffix %q", err.Error(), expectedMsg)
	}
}

func TestRouter_BuildBackendTransport_UnsupportedType(t *testing.T) {
	cfg := BackendConfig{
		Type: "unsupported",
	}

	_, err := buildBackendTransport(&backendConn{cfg: cfg})
	if err == nil {
		t.Fatal("expected error for unsupported backend type, got nil")
	}

	expectedMsg := "unsupported backend type"
	if err.Error()[:len(expectedMsg)] != expectedMsg {
		t.Errorf("error message = %q, want prefix %q", err.Error(), expectedMsg)
	}
}

func TestRouter_ListAllTools_EmptyBackends(t *testing.T) {
	cfg := []BackendConfig{}
	router := NewRouter(cfg)

	tools, err := router.ListAllTools(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tools) != 0 {
		t.Errorf("expected empty tools list, got %d tools", len(tools))
	}
}

func TestRouter_BuildBackendTransport_HTTP(t *testing.T) {
	cfg := BackendConfig{
		Type: "http",
		URL:  "https://mcp-server.example.com/mcp",
	}

	transport, err := buildBackendTransport(&backendConn{cfg: cfg})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
}

func TestRouter_BuildBackendTransport_HTTPMissingURL(t *testing.T) {
	cfg := BackendConfig{
		Type: "http",
		// URL is missing
	}

	_, err := buildBackendTransport(&backendConn{cfg: cfg})
	if err == nil {
		t.Fatal("expected error for http backend without URL, got nil")
	}

	expectedMsg := "requires a URL"
	if err.Error()[len(err.Error())-len(expectedMsg):] != expectedMsg {
		t.Errorf("error message = %q, want suffix %q", err.Error(), expectedMsg)
	}
}

func TestRouter_BuildBackendTransport_SSE(t *testing.T) {
	cfg := BackendConfig{
		Type: "sse",
		URL:  "https://mcp-server.example.com/sse",
	}

	transport, err := buildBackendTransport(&backendConn{cfg: cfg})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
	if _, ok := transport.(*mcp.SSEClientTransport); !ok {
		t.Errorf("expected *mcp.SSEClientTransport, got %T", transport)
	}
}

func TestRouter_BuildBackendTransport_SSEMissingURL(t *testing.T) {
	cfg := BackendConfig{
		Type: "sse",
	}

	_, err := buildBackendTransport(&backendConn{cfg: cfg})
	if err == nil {
		t.Fatal("expected error for sse backend without URL, got nil")
	}

	expectedMsg := "requires a URL"
	if err.Error()[len(err.Error())-len(expectedMsg):] != expectedMsg {
		t.Errorf("error message = %q, want suffix %q", err.Error(), expectedMsg)
	}
}

func TestCheckBackendURL_ValidPublicURL(t *testing.T) {
	if err := checkBackendURL("https://mcp.example.com/mcp", false); err != nil {
		t.Errorf("valid public URL rejected: %v", err)
	}
}

func TestCheckBackendURL_InvalidScheme(t *testing.T) {
	for _, rawURL := range []string{
		"ftp://mcp.example.com/mcp",
		"file:///etc/passwd",
		"ws://mcp.example.com/mcp",
	} {
		if err := checkBackendURL(rawURL, false); err == nil {
			t.Errorf("expected error for URL %q, got nil", rawURL)
		}
	}
}

func TestCheckBackendURL_PrivateIPRejected(t *testing.T) {
	privateURLs := []string{
		"http://10.0.0.1/mcp",
		"http://172.16.5.10/mcp",
		"http://192.168.1.100/mcp",
		"http://127.0.0.1/mcp",
	}
	for _, rawURL := range privateURLs {
		err := checkBackendURL(rawURL, false)
		if err == nil {
			t.Errorf("expected error for private URL %q, got nil", rawURL)
		} else if !strings.Contains(err.Error(), "private") && !strings.Contains(err.Error(), "loopback") {
			t.Errorf("error for %q should mention private/loopback, got: %v", rawURL, err)
		}
	}
}

func TestCheckBackendURL_PrivateIPAllowedWithFlag(t *testing.T) {
	privateURLs := []string{
		"http://10.0.0.1/mcp",
		"http://192.168.1.100/mcp",
		"http://127.0.0.1/mcp",
	}
	for _, rawURL := range privateURLs {
		if err := checkBackendURL(rawURL, true); err != nil {
			t.Errorf("private URL %q should be allowed when allow_private_addresses=true, got: %v", rawURL, err)
		}
	}
}

func TestCheckBackendURL_InvalidURL(t *testing.T) {
	if err := checkBackendURL("://not-a-url", false); err == nil {
		t.Error("expected error for malformed URL, got nil")
	}
}

func TestRouter_ResolveToolName_NoAlias(t *testing.T) {
	r := NewRouter([]BackendConfig{
		{Name: "backend", Type: "stdio", Command: "echo"},
	})
	if got := r.resolveToolName("backend", "query_db"); got != "query_db" {
		t.Errorf("resolveToolName = %q, want %q", got, "query_db")
	}
}

func TestRouter_ResolveToolName_WithAlias(t *testing.T) {
	r := NewRouter([]BackendConfig{})
	r.mu.Lock()
	r.backends["backend"] = &backendConn{
		cfg:         BackendConfig{Name: "backend", Type: "stdio", Command: "echo"},
		aliasToReal: map[string]string{"acme_query_db": "query_db"},
	}
	r.mu.Unlock()
	if got := r.resolveToolName("backend", "acme_query_db"); got != "query_db" {
		t.Errorf("resolveToolName = %q, want %q", got, "query_db")
	}
}

func TestRouter_ResolveToolName_UnknownBackend(t *testing.T) {
	r := NewRouter([]BackendConfig{})
	if got := r.resolveToolName("nonexistent", "tool"); got != "tool" {
		t.Errorf("resolveToolName for unknown backend = %q, want %q", got, "tool")
	}
}

func TestRouter_Reload_BuildsAliasToReal(t *testing.T) {
	r := NewRouter([]BackendConfig{
		{
			Name:    "backend",
			Type:    "stdio",
			Command: "echo",
			ToolMap: map[string]string{
				"query_database": "acme_query_database",
			},
		},
	})
	ctx := context.Background()
	_ = r.Reload(ctx, []BackendConfig{
		{
			Name:    "backend",
			Type:    "stdio",
			Command: "echo",
			ToolMap: map[string]string{
				"query_database": "acme_query_database",
			},
		},
	})

	r.mu.Lock()
	conn := r.backends["backend"]
	r.mu.Unlock()

	if conn.aliasToReal == nil {
		t.Fatal("aliasToReal should be populated after Reload")
	}
	if got := conn.aliasToReal["acme_query_database"]; got != "query_database" {
		t.Errorf("aliasToReal[%q] = %q, want %q", "acme_query_database", got, "query_database")
	}
	if got := r.resolveToolName("backend", "acme_query_database"); got != "query_database" {
		t.Errorf("resolveToolName = %q, want %q", got, "query_database")
	}
}

func TestRouter_Reload_DuplicateAliasAcrossBackends(t *testing.T) {
	r := NewRouter([]BackendConfig{
		{
			Name:    "backend_a",
			Type:    "stdio",
			Command: "echo",
			ToolMap: map[string]string{"tool_a": "shared_alias"},
		},
		{
			Name:    "backend_b",
			Type:    "stdio",
			Command: "echo",
			ToolMap: map[string]string{"tool_b": "shared_alias"},
		},
	})
	err := r.Reload(context.Background(), []BackendConfig{
		{
			Name:    "backend_a",
			Type:    "stdio",
			Command: "echo",
			ToolMap: map[string]string{"tool_a": "shared_alias"},
		},
		{
			Name:    "backend_b",
			Type:    "stdio",
			Command: "echo",
			ToolMap: map[string]string{"tool_b": "shared_alias"},
		},
	})
	if err == nil {
		t.Fatal("expected error for duplicate alias across backends, got nil")
	}
	if !strings.Contains(err.Error(), "shared_alias") {
		t.Errorf("error should mention the duplicate alias, got: %v", err)
	}
}

func TestRouter_Reload_UpdatesExistingBackendConfig(t *testing.T) {
	r := NewRouter([]BackendConfig{
		{Name: "backend", Type: "stdio", Command: "echo"},
	})
	newCfg := []BackendConfig{
		{
			Name:    "backend",
			Type:    "stdio",
			Command: "echo",
			ToolMap: map[string]string{"real_tool": "aliased_tool"},
		},
	}
	_ = r.Reload(context.Background(), newCfg)

	r.mu.Lock()
	conn := r.backends["backend"]
	r.mu.Unlock()

	if conn.aliasToReal == nil {
		t.Fatal("config update on reload should populate aliasToReal")
	}
	if conn.aliasToReal["aliased_tool"] != "real_tool" {
		t.Errorf("after config update, aliasToReal[%q] = %q, want %q",
			"aliased_tool", conn.aliasToReal["aliased_tool"], "real_tool")
	}
}

func makeTool(name string) *mcp.Tool {
	return &mcp.Tool{Name: name}
}

func TestBuildToolCache_NoCollision(t *testing.T) {
	surveys := []backendSurvey{
		{name: "a", tools: []*mcp.Tool{makeTool("foo"), makeTool("bar")}},
		{name: "b", tools: []*mcp.Tool{makeTool("baz")}},
	}
	all, err := buildToolCache(surveys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3 tools, got %d", len(all))
	}
}

func TestBuildToolCache_AliasApplied(t *testing.T) {
	surveys := []backendSurvey{
		{
			name:    "a",
			toolMap: map[string]string{"query_db": "acme_query_db"},
			tools:   []*mcp.Tool{makeTool("query_db"), makeTool("list_orders")},
		},
	}
	all, err := buildToolCache(surveys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	names := make(map[string]bool)
	for _, at := range all {
		names[at.Tool.Name] = true
	}
	if !names["acme_query_db"] {
		t.Error("expected aliased name \"acme_query_db\" in cache")
	}
	if names["query_db"] {
		t.Error("real name \"query_db\" should not appear in cache when aliased")
	}
}

func TestBuildToolCache_CollisionAliasVsUnaliased(t *testing.T) {
	surveys := []backendSurvey{
		{name: "a", toolMap: map[string]string{"bar": "foo"}, tools: []*mcp.Tool{makeTool("bar")}},
		{name: "b", tools: []*mcp.Tool{makeTool("foo")}},
	}
	_, err := buildToolCache(surveys)
	if err == nil {
		t.Fatal("expected collision error, got nil")
	}
	if !strings.Contains(err.Error(), "foo") {
		t.Errorf("error should mention colliding name \"foo\", got: %v", err)
	}
	if !strings.Contains(err.Error(), "alias") {
		t.Errorf("error should mention that one side is an alias, got: %v", err)
	}
}

func TestBuildToolCache_CollisionUnaliasedVsUnaliased(t *testing.T) {
	surveys := []backendSurvey{
		{name: "a", tools: []*mcp.Tool{makeTool("query_db")}},
		{name: "b", tools: []*mcp.Tool{makeTool("query_db")}},
	}
	_, err := buildToolCache(surveys)
	if err == nil {
		t.Fatal("expected collision error, got nil")
	}
	if !strings.Contains(err.Error(), "query_db") {
		t.Errorf("error should mention colliding name \"query_db\", got: %v", err)
	}
}

func TestBuildToolCache_CollisionAliasVsAlias(t *testing.T) {
	surveys := []backendSurvey{
		{name: "a", toolMap: map[string]string{"tool_a": "shared"}, tools: []*mcp.Tool{makeTool("tool_a")}},
		{name: "b", toolMap: map[string]string{"tool_b": "shared"}, tools: []*mcp.Tool{makeTool("tool_b")}},
	}
	_, err := buildToolCache(surveys)
	if err == nil {
		t.Fatal("expected collision error, got nil")
	}
	if !strings.Contains(err.Error(), "shared") {
		t.Errorf("error should mention colliding name \"shared\", got: %v", err)
	}
}

func TestBuildToolCache_OriginalToolUnmutated(t *testing.T) {
	orig := makeTool("real_name")
	surveys := []backendSurvey{
		{name: "a", toolMap: map[string]string{"real_name": "alias_name"}, tools: []*mcp.Tool{orig}},
	}
	all, err := buildToolCache(surveys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if orig.Name != "real_name" {
		t.Errorf("original tool was mutated: Name = %q", orig.Name)
	}
	if all[0].Tool.Name != "alias_name" {
		t.Errorf("cached tool name = %q, want \"alias_name\"", all[0].Tool.Name)
	}
}

func TestNoRedirectHTTPClient_RefusesRedirect(t *testing.T) {
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()

	redirectSource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer redirectSource.Close()

	client := noRedirectHTTPClient()
	resp, err := client.Get(redirectSource.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Error("expected error when server redirects, got nil")
	}
	if !strings.Contains(err.Error(), "redirects are not permitted") {
		t.Errorf("error should mention redirect prohibition, got: %v", err)
	}
}
