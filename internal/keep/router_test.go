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
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
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

// --- injectAtPath ---

func TestInjectAtPath_TopLevel(t *testing.T) {
	m := map[string]any{"existing": "val"}
	injectAtPath(m, "token", "tok123")
	if m["token"] != "tok123" {
		t.Errorf("m[\"token\"] = %v, want %q", m["token"], "tok123")
	}
	if m["existing"] != "val" {
		t.Error("injectAtPath mutated unrelated key")
	}
}

func TestInjectAtPath_Nested(t *testing.T) {
	m := map[string]any{}
	injectAtPath(m, "a.b.c", "deep-value")
	ab, ok := m["a"].(map[string]any)
	if !ok {
		t.Fatalf("m[\"a\"] is not a map: %T", m["a"])
	}
	abc, ok := ab["b"].(map[string]any)
	if !ok {
		t.Fatalf("m[\"a\"][\"b\"] is not a map: %T", ab["b"])
	}
	if abc["c"] != "deep-value" {
		t.Errorf("m[\"a\"][\"b\"][\"c\"] = %v, want %q", abc["c"], "deep-value")
	}
}

func TestInjectAtPath_OverwritesExistingLeaf(t *testing.T) {
	m := map[string]any{"key": "old"}
	injectAtPath(m, "key", "new")
	if m["key"] != "new" {
		t.Errorf("m[\"key\"] = %v, want %q", m["key"], "new")
	}
}

func TestInjectAtPath_ReplacesNonMapIntermediate(t *testing.T) {
	// "a" exists as a string but path expects it to be a map.
	m := map[string]any{"a": "not-a-map"}
	injectAtPath(m, "a.b", "value")
	aMap, ok := m["a"].(map[string]any)
	if !ok {
		t.Fatalf("m[\"a\"] should have been replaced by a map, got %T", m["a"])
	}
	if aMap["b"] != "value" {
		t.Errorf("m[\"a\"][\"b\"] = %v, want %q", aMap["b"], "value")
	}
}

func TestInjectAtPath_PreservesExistingIntermediateMap(t *testing.T) {
	m := map[string]any{
		"a": map[string]any{"existing": "keep"},
	}
	injectAtPath(m, "a.new", "injected")
	aMap := m["a"].(map[string]any)
	if aMap["existing"] != "keep" {
		t.Error("injectAtPath clobbered existing intermediate map key")
	}
	if aMap["new"] != "injected" {
		t.Errorf("aMap[\"new\"] = %v, want %q", aMap["new"], "injected")
	}
}

func TestInjectAtPath_DoesNotMutateOriginalNestedMap(t *testing.T) {
	// Regression test: a shallow copy of the top-level args is not sufficient
	// when the injection path traverses a nested map that the copy still shares
	// with the original. injectAtPath must copy every intermediate map so the
	// original args are never modified.
	sharedInner := map[string]any{"existing": "original"}
	orig := map[string]any{"auth": sharedInner}

	// Simulate what CallTool does: shallow top-level copy then inject.
	argsCopy := make(map[string]any, len(orig))
	for k, v := range orig {
		argsCopy[k] = v
	}
	injectAtPath(argsCopy, "auth.token", "injected-jwt")

	// The original shared inner map must be untouched.
	if _, mutated := sharedInner["token"]; mutated {
		t.Error("privacy mandate violated: injectAtPath mutated the original nested map")
	}
	if sharedInner["existing"] != "original" {
		t.Error("injectAtPath corrupted an unrelated key in the original nested map")
	}

	// The copy must have the injected value without affecting the original.
	authCopy, ok := argsCopy["auth"].(map[string]any)
	if !ok {
		t.Fatalf("argsCopy[\"auth\"] is not a map: %T", argsCopy["auth"])
	}
	if authCopy["token"] != "injected-jwt" {
		t.Errorf("argsCopy[\"auth\"][\"token\"] = %v, want %q", authCopy["token"], "injected-jwt")
	}
	// The copy's inner map must be a different allocation than the original's.
	// Compare via reflect to get pointer identity without direct map comparison.
	if reflect.ValueOf(authCopy).Pointer() == reflect.ValueOf(sharedInner).Pointer() {
		t.Error("argsCopy[\"auth\"] is the same map pointer as the original — mutation is possible")
	}
}

// --- identity body injection in CallTool ---

// newCapturingMCPBackend starts a real MCP-over-HTTP test server with a single
// "test_tool" tool. The tool handler captures the raw arguments map it receives
// and returns a trivial success result. The returned getArgs function retrieves
// the last captured arguments; it returns nil if the tool has not been called.
//
// The server uses mcp.NewStreamableHTTPHandler so the full Router→MCP session
// path is exercised, including the injection logic inside Router.CallTool.
func newCapturingMCPBackend(t *testing.T) (backendURL string, getArgs func() map[string]any) {
	t.Helper()

	var mu sync.Mutex
	var lastArgs map[string]any

	server := mcp.NewServer(&mcp.Implementation{Name: "test-backend", Version: "1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "test_tool"},
		func(_ context.Context, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
			mu.Lock()
			lastArgs = args
			mu.Unlock()
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "ok"}},
			}, nil, nil
		},
	)

	mux := http.NewServeMux()
	mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return server }, nil,
	))
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		// Force-close keep-alive connections held by the MCP client before
		// shutting the server down, otherwise Close blocks indefinitely.
		srv.CloseClientConnections()
		srv.Close()
	})

	return srv.URL + "/mcp", func() map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return lastArgs
	}
}

// TestCallTool_BodyInjection_TokenReachesBackend calls Router.CallTool with a
// raw token in the context and verifies that the token appears at the
// configured IdentityPath inside the arguments received by the backend.
func TestCallTool_BodyInjection_TokenReachesBackend(t *testing.T) {
	backendURL, getArgs := newCapturingMCPBackend(t)

	r := NewRouter([]BackendConfig{{
		Name:                  "b",
		Type:                  "http",
		URL:                   backendURL,
		AllowPrivateAddresses: true,
		UserIdentity: BackendUserIdentity{Placement: BackendIdentityPlacement{JSONPath: "auth.token"}},
	}})

	origArgs := map[string]any{"param": "value"}
	ctx := withRawToken(context.Background(), "jwt-abc")

	if _, err := r.CallTool(ctx, "b", "test_tool", origArgs); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	captured := getArgs()
	if captured == nil {
		t.Fatal("backend did not receive a tool call")
	}
	auth, ok := captured["auth"].(map[string]any)
	if !ok {
		t.Fatalf("captured[\"auth\"] is not a map: %T", captured["auth"])
	}
	if auth["token"] != "jwt-abc" {
		t.Errorf("injected token = %v, want %q", auth["token"], "jwt-abc")
	}
	// The original args must not be mutated by the injection.
	if _, mutated := origArgs["auth"]; mutated {
		t.Error("original args were mutated — privacy mandate violated")
	}
}

// TestCallTool_BodyInjection_SkipsWhenNoToken calls Router.CallTool without a
// raw token in the context and verifies that the backend receives the original
// arguments unchanged — no injection key is added.
func TestCallTool_BodyInjection_SkipsWhenNoToken(t *testing.T) {
	backendURL, getArgs := newCapturingMCPBackend(t)

	r := NewRouter([]BackendConfig{{
		Name:                  "b",
		Type:                  "http",
		URL:                   backendURL,
		AllowPrivateAddresses: true,
		UserIdentity: BackendUserIdentity{Placement: BackendIdentityPlacement{JSONPath: "auth.token"}},
	}})

	origArgs := map[string]any{"param": "value"}

	// context.Background() carries no raw token.
	if _, err := r.CallTool(context.Background(), "b", "test_tool", origArgs); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	captured := getArgs()
	if captured == nil {
		t.Fatal("backend did not receive a tool call")
	}
	if _, injected := captured["auth"]; injected {
		t.Error("injection key present even though no token was in context")
	}
	if captured["param"] != "value" {
		t.Errorf("original param lost: captured[\"param\"] = %v", captured["param"])
	}
}

// TestCallTool_BodyInjection_NestedMapNotMutated verifies that when args
// already contain a nested map at the injection path, Router.CallTool does not
// mutate the original nested map — only the copy sent to the backend is updated.
func TestCallTool_BodyInjection_NestedMapNotMutated(t *testing.T) {
	backendURL, getArgs := newCapturingMCPBackend(t)

	r := NewRouter([]BackendConfig{{
		Name:                  "b",
		Type:                  "http",
		URL:                   backendURL,
		AllowPrivateAddresses: true,
		UserIdentity: BackendUserIdentity{Placement: BackendIdentityPlacement{JSONPath: "auth.token"}},
	}})

	// The inner map is shared between origArgs and our local reference.
	sharedInner := map[string]any{"existing": "original"}
	origArgs := map[string]any{"auth": sharedInner, "other": "keep"}
	ctx := withRawToken(context.Background(), "jwt-abc")

	if _, err := r.CallTool(ctx, "b", "test_tool", origArgs); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	// The backend must have received the injected token.
	captured := getArgs()
	if captured == nil {
		t.Fatal("backend did not receive a tool call")
	}
	capturedAuth, ok := captured["auth"].(map[string]any)
	if !ok {
		t.Fatalf("captured[\"auth\"] is not a map: %T", captured["auth"])
	}
	if capturedAuth["token"] != "jwt-abc" {
		t.Errorf("backend did not receive injected token: captured auth = %v", capturedAuth)
	}

	// The original shared inner map must be completely untouched.
	if _, mutated := sharedInner["token"]; mutated {
		t.Error("privacy mandate violated: Router.CallTool mutated the original nested map")
	}
	if sharedInner["existing"] != "original" {
		t.Errorf("Router.CallTool corrupted unrelated key: sharedInner[\"existing\"] = %v", sharedInner["existing"])
	}
}

// --- static tool routing ---

func TestRouter_ListTools_Static(t *testing.T) {
	mockTool := &mcp.Tool{
		Name:        "static_tool",
		Description: "A static tool",
	}

	cfg := BackendConfig{
		Name: "static_backend",
		ToolList: ToolListConfig{
			Source: "file",
		},
		StaticTools: []*mcp.Tool{mockTool},
	}

	router := NewRouter([]BackendConfig{cfg})

	tools, err := router.ListTools(context.Background(), "static_backend")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tools) != 1 || tools[0].Name != "static_tool" {
		t.Errorf("expected to get static tool, got: %+v", tools)
	}
}

// --- config validation ---

func TestValidateBackendConfig_Valid(t *testing.T) {
	cases := []BackendConfig{
		{UserIdentity: BackendUserIdentity{Placement: BackendIdentityPlacement{Header: "X-Identity-Token"}}},
		{UserIdentity: BackendUserIdentity{Placement: BackendIdentityPlacement{JSONPath: "auth.token"}}},
		{}, // neither set — always valid
	}
	for _, cfg := range cases {
		if err := validateBackendConfig(&cfg); err != nil {
			t.Errorf("validateBackendConfig(%+v) = %v, want nil", cfg, err)
		}
	}
}

func TestValidateBackendConfig_BothPlacementFieldsRejected(t *testing.T) {
	cfg := BackendConfig{UserIdentity: BackendUserIdentity{Placement: BackendIdentityPlacement{
		Header:   "X-Identity-Token",
		JSONPath: "auth.token",
	}}}
	if err := validateBackendConfig(&cfg); err == nil {
		t.Error("expected error when both header and json_path are set, got nil")
	}
}

func TestValidateBackendConfig_ExchangeURLWithoutPlacementRejected(t *testing.T) {
	cfg := BackendConfig{
		AllowPrivateAddresses: true,
		UserIdentity: BackendUserIdentity{
			Exchange: BackendIdentityExchange{URL: "http://exchange.internal/exchange"},
		},
	}
	if err := validateBackendConfig(&cfg); err == nil {
		t.Error("expected error when exchange.url is set but no placement is configured, got nil")
	}
}

func TestValidateBackendConfig_ForbiddenHeader(t *testing.T) {
	forbidden := []string{
		"Host", "Content-Length", "Transfer-Encoding", "Connection",
		"X-Portcullis-Trace",
	}
	for _, h := range forbidden {
		cfg := BackendConfig{UserIdentity: BackendUserIdentity{Placement: BackendIdentityPlacement{Header: h}}}
		if err := validateBackendConfig(&cfg); err == nil {
			t.Errorf("expected error for forbidden identity_header %q, got nil", h)
		}
	}
}

func TestValidateBackendConfig_InvalidPath(t *testing.T) {
	badPaths := []string{
		// empty / whitespace-only
		" ",
		"\t",
		"  ",
		// empty segments
		".leading",
		"trailing.",
		"a..b",
		".",
		// invalid characters within a segment
		"a b",        // space inside segment
		"a.b c",      // space in nested segment
		"auth.tok$en", // dollar sign
		"auth.tok@en", // at sign
		"a.b/c",      // slash
		"a.b.c!",     // exclamation
	}
	for _, p := range badPaths {
		cfg := BackendConfig{UserIdentity: BackendUserIdentity{Placement: BackendIdentityPlacement{JSONPath: p}}}
		if err := validateBackendConfig(&cfg); err == nil {
			t.Errorf("expected error for malformed json_path %q, got nil", p)
		}
	}
}

func TestValidateBackendConfig_ValidPaths(t *testing.T) {
	good := []string{
		"token",
		"auth.token",
		"a.b.c.d",
		"auth_token",
		"x-identity",
		"Auth-Token-123",
	}
	for _, p := range good {
		cfg := BackendConfig{UserIdentity: BackendUserIdentity{Placement: BackendIdentityPlacement{JSONPath: p}}}
		if err := validateBackendConfig(&cfg); err != nil {
			t.Errorf("validateBackendConfig with path %q = %v, want nil", p, err)
		}
	}
}

func TestValidateBackendConfig_StaticToolList(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "tools.json")

	toolsData := `{
		"tools": [
			{
				"name": "static_tool",
				"description": "A tool loaded from a file"
			}
		]
	}`
	if err := os.WriteFile(filePath, []byte(toolsData), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	cfg := BackendConfig{
		ToolList: ToolListConfig{
			Source: "file",
			File:   filePath,
		},
	}

	if err := validateBackendConfig(&cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.StaticTools) != 1 || cfg.StaticTools[0].Name != "static_tool" {
		t.Errorf("failed to load static tools correctly: %+v", cfg.StaticTools)
	}
}

func TestValidateBackendConfig_StaticToolListErrors(t *testing.T) {
	cfgNoFile := BackendConfig{
		ToolList: ToolListConfig{Source: "file"},
	}
	if err := validateBackendConfig(&cfgNoFile); err == nil {
		t.Error("expected error when source is file but no file is provided")
	}

	cfgInvalidSource := BackendConfig{
		ToolList: ToolListConfig{Source: "invalid"},
	}
	if err := validateBackendConfig(&cfgInvalidSource); err == nil {
		t.Error("expected error for invalid source")
	}

	cfgMissingFile := BackendConfig{
		ToolList: ToolListConfig{
			Source: "file",
			File:   "missing/relative/path.json",
		},
	}
	err := validateBackendConfig(&cfgMissingFile)
	if err == nil {
		t.Error("expected error for missing file")
	} else {
		errMsg := err.Error()
		if !strings.Contains(errMsg, "attempted=") || !strings.Contains(errMsg, "base_dir=") {
			t.Errorf("error message missing diagnostic info, got: %v", errMsg)
		}
		parts := strings.SplitN(errMsg, "attempted=\"", 2)
		if len(parts) == 2 {
			pathPart := strings.SplitN(parts[1], "\"", 2)[0]
			if !filepath.IsAbs(pathPart) {
				t.Errorf("expected attempted path to be absolute, got: %q", pathPart)
			}
		} else {
			t.Errorf("could not extract attempted path from error: %v", errMsg)
		}
	}

	tmpDir := t.TempDir()
	malformedPath := filepath.Join(tmpDir, "malformed.json")
	_ = os.WriteFile(malformedPath, []byte("{ not valid json "), 0644)

	cfgMalformedFile := BackendConfig{
		ToolList: ToolListConfig{
			Source: "file",
			File:   malformedPath,
		},
	}
	err = validateBackendConfig(&cfgMalformedFile)
	if err == nil {
		t.Error("expected error for malformed file")
	} else {
		errMsg := err.Error()
		if !strings.Contains(errMsg, "configured=") || !strings.Contains(errMsg, "attempted=") {
			t.Errorf("error message missing diagnostic info, got: %v", errMsg)
		}
	}
}

func TestValidateBackendConfig_EnforceAuthToolList(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	refPath := filepath.Join(filepath.Dir(thisFile), "../../examples/tool-lists/enforceauth_mcp.json")

	cfg := BackendConfig{
		ToolList: ToolListConfig{
			Source: "file",
			File:   refPath,
		},
	}

	if err := validateBackendConfig(&cfg); err != nil {
		t.Fatalf("enforceauth_mcp.json failed to parse: %v", err)
	}

	if len(cfg.StaticTools) == 0 {
		t.Fatal("expected tools to be loaded, got none")
	}

	if cfg.StaticTools[0].Name != "ea_me" {
		t.Errorf("expected first tool to be ea_me, got %q", cfg.StaticTools[0].Name)
	}

	t.Logf("loaded %d tools from enforceauth_mcp.json", len(cfg.StaticTools))
}

func TestValidateBackendConfig_UnifiedIdentityTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cfg     BackendConfig
		wantErr bool
		errFrag string
	}{
		{
			name: "type oauth valid",
			cfg: BackendConfig{
				AllowPrivateAddresses: true,
				UserIdentity: BackendUserIdentity{
					Type: "oauth",
					OAuth: BackendOAuth{
						ClientID:              "cid",
						AuthorizationEndpoint: "https://auth.example/authorize",
						TokenEndpoint:         "https://auth.example/token",
						CallbackURL:           "https://keep.example/oauth/callback",
					},
				},
			},
		},
		{
			name: "type oauth missing client_id",
			cfg: BackendConfig{
				UserIdentity: BackendUserIdentity{
					Type: "oauth",
					OAuth: BackendOAuth{
						AuthorizationEndpoint: "https://auth.example/authorize",
						TokenEndpoint:         "https://auth.example/token",
						CallbackURL:           "https://keep.example/oauth/callback",
					},
				},
			},
			wantErr: true,
			errFrag: "client_id",
		},
		{
			name: "type oauth missing authorization_endpoint",
			cfg: BackendConfig{
				UserIdentity: BackendUserIdentity{
					Type: "oauth",
					OAuth: BackendOAuth{
						ClientID:    "cid",
						TokenEndpoint: "https://auth.example/token",
						CallbackURL:  "https://keep.example/oauth/callback",
					},
				},
			},
			wantErr: true,
			errFrag: "authorization_endpoint",
		},
		{
			name: "type api_key valid",
			cfg: BackendConfig{
				UserIdentity: BackendUserIdentity{
					Type:      "api_key",
					Placement: BackendIdentityPlacement{Header: "X-Api-Key"},
					APIKey:    BackendAPIKey{Source: "my-secret-key"},
				},
			},
		},
		{
			name: "type api_key missing source",
			cfg: BackendConfig{
				UserIdentity: BackendUserIdentity{
					Type:      "api_key",
					Placement: BackendIdentityPlacement{Header: "X-Api-Key"},
				},
			},
			wantErr: true,
			errFrag: "api_key.source",
		},
		{
			name: "type api_key missing header",
			cfg: BackendConfig{
				UserIdentity: BackendUserIdentity{
					Type:   "api_key",
					APIKey: BackendAPIKey{Source: "secret"},
				},
			},
			wantErr: true,
			errFrag: "placement.header",
		},
		{
			name: "type exchange valid",
			cfg: BackendConfig{
				AllowPrivateAddresses: true,
				UserIdentity: BackendUserIdentity{
					Type:      "exchange",
					Placement: BackendIdentityPlacement{Header: "X-Identity"},
					Exchange:  BackendIdentityExchange{URL: "http://exchange.internal/v1"},
				},
			},
		},
		{
			name: "type exchange missing url",
			cfg: BackendConfig{
				UserIdentity: BackendUserIdentity{
					Type:      "exchange",
					Placement: BackendIdentityPlacement{Header: "X-Identity"},
				},
			},
			wantErr: true,
			errFrag: "exchange.url",
		},
		{
			name: "invalid type",
			cfg: BackendConfig{
				UserIdentity: BackendUserIdentity{Type: "magic"},
			},
			wantErr: true,
			errFrag: "invalid",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBackendConfig(&tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.errFrag)
				} else if tc.errFrag != "" && !strings.Contains(err.Error(), tc.errFrag) {
					t.Errorf("error %q does not contain %q", err, tc.errFrag)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPKCEHelpers(t *testing.T) {
	t.Parallel()

	verifier, err := generatePKCEVerifier()
	if err != nil {
		t.Fatalf("generatePKCEVerifier: %v", err)
	}
	if len(verifier) < 40 {
		t.Errorf("verifier too short: %q", verifier)
	}

	challenge := pkceChallenge(verifier)
	if len(challenge) == 0 {
		t.Error("empty challenge")
	}
	// Different verifiers must produce different challenges.
	v2, _ := generatePKCEVerifier()
	if pkceChallenge(v2) == challenge {
		t.Error("different verifiers should produce different challenges")
	}

	nonce, err := generateNonce()
	if err != nil {
		t.Fatalf("generateNonce: %v", err)
	}
	if len(nonce) == 0 {
		t.Error("empty nonce")
	}
}

func TestBuildAuthURL(t *testing.T) {
	t.Parallel()
	u := buildAuthURL("https://auth.example/authorize", "client-id", "https://keep.example/cb",
		[]string{"read", "write"}, "state-123", "challenge-abc")
	if !strings.Contains(u, "response_type=code") {
		t.Errorf("missing response_type: %s", u)
	}
	if !strings.Contains(u, "code_challenge_method=S256") {
		t.Errorf("missing code_challenge_method: %s", u)
	}
	if !strings.Contains(u, "state=state-123") {
		t.Errorf("missing state: %s", u)
	}
	if !strings.Contains(u, "scope=read+write") && !strings.Contains(u, "scope=read%20write") {
		t.Errorf("missing scope: %s", u)
	}
}

func TestRouter_TryStartOAuthFlow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	credStore := NewMemoryCredentialsStore()

	r := &Router{
		backends:  make(map[string]*backendConn),
		credStore: credStore,
	}
	r.backends["my-backend"] = &backendConn{
		cfg: BackendConfig{
			Name: "my-backend",
			UserIdentity: BackendUserIdentity{
				Type: "oauth",
				OAuth: BackendOAuth{
					ClientID:              "cid",
					AuthorizationEndpoint: "https://auth.example/authorize",
					TokenEndpoint:         "https://auth.example/token",
					CallbackURL:           "https://keep.example/oauth/callback",
					Scopes:                []string{"openid", "api"},
				},
			},
		},
	}

	result, err := r.tryStartOAuthFlow(ctx, "my-backend", "user-1")
	if err != nil {
		t.Fatalf("tryStartOAuthFlow: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for auth URL result")
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "https://auth.example/authorize") {
		t.Errorf("result text missing auth URL: %q", text)
	}
	if !strings.Contains(text, "code_challenge_method=S256") {
		t.Errorf("result text missing PKCE challenge method: %q", text)
	}

	// Verify pending state was stored.
	// Extract the state parameter from the URL in the text.
	stateStart := strings.Index(text, "state=")
	if stateStart < 0 {
		t.Fatal("no state parameter in URL")
	}
	stateStr := text[stateStart+6:]
	if amp := strings.IndexAny(stateStr, "& \n"); amp >= 0 {
		stateStr = stateStr[:amp]
	}
	pending, err := credStore.ConsumePending(ctx, stateStr)
	if err != nil || pending == nil {
		t.Fatalf("pending state not found for nonce %q: %v", stateStr, err)
	}
	if pending.BackendName != "my-backend" || pending.UserID != "user-1" {
		t.Errorf("pending mismatch: %+v", pending)
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
