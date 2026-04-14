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
	"reflect"
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
		IdentityPath:          "auth.token",
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
		IdentityPath:          "auth.token",
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
		IdentityPath:          "auth.token",
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

// --- config validation ---

func TestValidateBackendIdentityConfig_Valid(t *testing.T) {
	cases := []BackendConfig{
		{IdentityHeader: "X-Identity-Token"},
		{IdentityPath: "auth.token"},
		{IdentityHeader: "X-User-JWT", IdentityPath: "identity.jwt"},
		{}, // neither set — always valid
	}
	for _, cfg := range cases {
		if err := validateBackendIdentityConfig(cfg); err != nil {
			t.Errorf("validateBackendIdentityConfig(%+v) = %v, want nil", cfg, err)
		}
	}
}

func TestValidateBackendIdentityConfig_ForbiddenHeader(t *testing.T) {
	forbidden := []string{
		"Host", "Content-Length", "Transfer-Encoding", "Connection",
		"X-Portcullis-Trace",
	}
	for _, h := range forbidden {
		cfg := BackendConfig{IdentityHeader: h}
		if err := validateBackendIdentityConfig(cfg); err == nil {
			t.Errorf("expected error for forbidden identity_header %q, got nil", h)
		}
	}
}

func TestValidateBackendIdentityConfig_InvalidPath(t *testing.T) {
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
		cfg := BackendConfig{IdentityPath: p}
		if err := validateBackendIdentityConfig(cfg); err == nil {
			t.Errorf("expected error for malformed identity_path %q, got nil", p)
		}
	}
}

func TestValidateBackendIdentityConfig_ValidPaths(t *testing.T) {
	good := []string{
		"token",
		"auth.token",
		"a.b.c.d",
		"auth_token",
		"x-identity",
		"Auth-Token-123",
	}
	for _, p := range good {
		cfg := BackendConfig{IdentityPath: p}
		if err := validateBackendIdentityConfig(cfg); err != nil {
			t.Errorf("validateBackendIdentityConfig with path %q = %v, want nil", p, err)
		}
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
