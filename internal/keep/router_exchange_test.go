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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// newCapturingMCPBackendWithHeaders is like newCapturingMCPBackend but also
// captures the HTTP request headers from each inbound request so that
// identity header injection can be verified at the router level.
func newCapturingMCPBackendWithHeaders(t *testing.T) (
	backendURL string,
	getArgs func() map[string]any,
	getLastHeaders func() http.Header,
) {
	t.Helper()

	var mu sync.Mutex
	var lastArgs map[string]any
	var lastHeaders http.Header

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

	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return server }, nil,
	)

	mux := http.NewServeMux()
	mux.Handle("/mcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastHeaders = r.Header.Clone()
		mu.Unlock()
		mcpHandler.ServeHTTP(w, r)
	}))

	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
	})

	return srv.URL + "/mcp",
		func() map[string]any { mu.Lock(); defer mu.Unlock(); return lastArgs },
		func() http.Header { mu.Lock(); defer mu.Unlock(); return lastHeaders }
}

// newSuccessExchangeServer returns an httptest.Server that responds with the
// given exchanged identity value.
func newSuccessExchangeServer(t *testing.T, exchangedValue string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"identity":%q}`, exchangedValue)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newFailingExchangeServer returns an httptest.Server that always responds
// with a 503, triggering fail-degraded behavior in the exchange client.
func newFailingExchangeServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "exchange service unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// installExchanger replaces the IdentityExchanger for backendName on r with
// a live IdentityExchangeClient pointed at exchangeSrvURL.
func installExchanger(r *Router, backendName, exchangeSrvURL string) {
	hc := noRedirectHTTPClient()
	hc.Timeout = 5 * time.Second
	client := &IdentityExchangeClient{
		url:         exchangeSrvURL,
		backendName: backendName,
		httpClient:  hc,
	}
	r.exchangeMu.Lock()
	r.exchangers[backendName] = client
	r.exchangeMu.Unlock()
}

// --- body (IdentityPath) injection with exchange ---

// TestCallTool_Exchange_BodyInjection_ExchangedTokenForwarded verifies that
// when exchange succeeds the exchanged value (not the original raw token) is
// injected at the configured IdentityPath in the backend's tool arguments.
func TestCallTool_Exchange_BodyInjection_ExchangedTokenForwarded(t *testing.T) {
	backendURL, getArgs := newCapturingMCPBackend(t)
	exchangeSrv := newSuccessExchangeServer(t, "enterprise-user-99")

	r := NewRouter([]BackendConfig{{
		Name:                  "b",
		Type:                  "http",
		URL:                   backendURL,
		AllowPrivateAddresses: true,
		UserIdentity: BackendUserIdentity{Placement: BackendIdentityPlacement{JSONPath: "auth.token"}},
	}})
	installExchanger(r, "b", exchangeSrv.URL)

	ctx := withRawToken(context.Background(), "jwt-original")
	if _, err := r.CallTool(ctx, "b", "test_tool", map[string]any{"param": "v"}); err != nil {
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
	if auth["token"] != "enterprise-user-99" {
		t.Errorf("injected token = %v, want %q", auth["token"], "enterprise-user-99")
	}
	if auth["token"] == "jwt-original" {
		t.Error("original raw token was forwarded — exchange result must replace it")
	}
}

// TestCallTool_Exchange_BodyInjection_FailDegraded_NoInjection verifies that
// when exchange fails the identity path key is absent from the backend's
// arguments and the original raw token is not present anywhere in the args.
func TestCallTool_Exchange_BodyInjection_FailDegraded_NoInjection(t *testing.T) {
	backendURL, getArgs := newCapturingMCPBackend(t)
	exchangeSrv := newFailingExchangeServer(t)

	r := NewRouter([]BackendConfig{{
		Name:                  "b",
		Type:                  "http",
		URL:                   backendURL,
		AllowPrivateAddresses: true,
		UserIdentity: BackendUserIdentity{Placement: BackendIdentityPlacement{JSONPath: "auth.token"}},
	}})
	installExchanger(r, "b", exchangeSrv.URL)

	ctx := withRawToken(context.Background(), "jwt-original")
	if _, err := r.CallTool(ctx, "b", "test_tool", map[string]any{"param": "v"}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	captured := getArgs()
	if captured == nil {
		t.Fatal("backend did not receive a tool call")
	}

	// The injection path must be absent.
	if _, injected := captured["auth"]; injected {
		t.Error("identity path was injected despite exchange failure")
	}

	// The original token must not appear anywhere in the serialized args.
	argsJSON, _ := json.Marshal(captured)
	if strings.Contains(string(argsJSON), "jwt-original") {
		t.Errorf("original raw token found in backend args despite exchange failure: %s", argsJSON)
	}
}

// --- header (IdentityHeader) injection with exchange ---

// TestCallTool_Exchange_HeaderInjection_ExchangedValueForwarded verifies that
// when exchange succeeds the exchanged value (not the original raw token) is
// set as the configured IdentityHeader on requests to the backend.
func TestCallTool_Exchange_HeaderInjection_ExchangedValueForwarded(t *testing.T) {
	backendURL, _, getLastHeaders := newCapturingMCPBackendWithHeaders(t)
	exchangeSrv := newSuccessExchangeServer(t, "enterprise-user-99")

	r := NewRouter([]BackendConfig{{
		Name:                  "b",
		Type:                  "http",
		URL:                   backendURL,
		AllowPrivateAddresses: true,
		UserIdentity: BackendUserIdentity{Placement: BackendIdentityPlacement{Header: "X-Enterprise-ID"}},
	}})
	installExchanger(r, "b", exchangeSrv.URL)

	ctx := withRawToken(context.Background(), "jwt-original")
	if _, err := r.CallTool(ctx, "b", "test_tool", nil); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	headers := getLastHeaders()
	got := headers.Get("X-Enterprise-Id")
	if got != "enterprise-user-99" {
		t.Errorf("X-Enterprise-ID = %q, want %q", got, "enterprise-user-99")
	}
	if got == "jwt-original" {
		t.Error("original raw token was forwarded as identity header — exchange result must replace it")
	}
}

// TestCallTool_Exchange_HeaderInjection_FailDegraded_HeaderAbsent verifies that
// when exchange fails the identity header is not present on requests to the
// backend — neither the exchanged value nor the original raw token is forwarded.
func TestCallTool_Exchange_HeaderInjection_FailDegraded_HeaderAbsent(t *testing.T) {
	backendURL, _, getLastHeaders := newCapturingMCPBackendWithHeaders(t)
	exchangeSrv := newFailingExchangeServer(t)

	r := NewRouter([]BackendConfig{{
		Name:                  "b",
		Type:                  "http",
		URL:                   backendURL,
		AllowPrivateAddresses: true,
		UserIdentity: BackendUserIdentity{Placement: BackendIdentityPlacement{Header: "X-Enterprise-ID"}},
	}})
	installExchanger(r, "b", exchangeSrv.URL)

	ctx := withRawToken(context.Background(), "jwt-original")
	if _, err := r.CallTool(ctx, "b", "test_tool", nil); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	headers := getLastHeaders()

	// The identity header must be absent.
	if val := headers.Get("X-Enterprise-Id"); val != "" {
		t.Errorf("X-Enterprise-ID header present despite exchange failure: %q", val)
	}

	// The original token must not appear in any header value.
	for name, vals := range headers {
		for _, v := range vals {
			if strings.Contains(v, "jwt-original") {
				t.Errorf("original raw token found in header %q: %q", name, v)
			}
		}
	}
}

// --- Reload exchanger construction ---

// TestReload_WithExchangeURL_BuildsRealClientAndInjectsExchangedValue verifies
// that calling Reload with a backend that has user_identity.exchange.url set
// constructs a live IdentityExchangeClient (not the initial failDegradedExchanger)
// and that a subsequent CallTool injects the exchanged value — not the raw token.
func TestReload_WithExchangeURL_BuildsRealClientAndInjectsExchangedValue(t *testing.T) {
	backendURL, getArgs := newCapturingMCPBackend(t)
	exchangeSrv := newSuccessExchangeServer(t, "reloaded-identity-42")

	cfg := BackendConfig{
		Name:                  "b",
		Type:                  "http",
		URL:                   backendURL,
		AllowPrivateAddresses: true,
		UserIdentity: BackendUserIdentity{
			Placement: BackendIdentityPlacement{JSONPath: "auth.token"},
			Exchange:  BackendIdentityExchange{URL: exchangeSrv.URL},
		},
	}

	r := NewRouter([]BackendConfig{cfg})

	// Before Reload the exchanger is failDegradedExchanger — verify the type.
	r.exchangeMu.RLock()
	before := r.exchangers["b"]
	r.exchangeMu.RUnlock()
	if _, ok := before.(failDegradedExchanger); !ok {
		t.Fatalf("before Reload: expected failDegradedExchanger, got %T", before)
	}

	// Reload should build a real IdentityExchangeClient.
	if err := r.Reload(context.Background(), []BackendConfig{cfg}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	r.exchangeMu.RLock()
	after := r.exchangers["b"]
	r.exchangeMu.RUnlock()
	if _, ok := after.(*IdentityExchangeClient); !ok {
		t.Fatalf("after Reload: expected *IdentityExchangeClient, got %T", after)
	}

	// A tool call must inject the exchanged value.
	ctx := withRawToken(context.Background(), "raw-jwt")
	if _, err := r.CallTool(ctx, "b", "test_tool", map[string]any{}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	captured := getArgs()
	auth, ok := captured["auth"].(map[string]any)
	if !ok {
		t.Fatalf("captured[\"auth\"] not a map: %T", captured["auth"])
	}
	if auth["token"] != "reloaded-identity-42" {
		t.Errorf("injected token = %v, want %q", auth["token"], "reloaded-identity-42")
	}
	if auth["token"] == "raw-jwt" {
		t.Error("raw token was forwarded — exchange result must replace it")
	}
}

// TestReload_WithRedisExchangeCache_FailsWhenRedisUnavailable verifies that
// Reload returns a hard error when the exchange cache backend is Redis and
// Redis is not reachable — ensuring the process fails fast rather than limping
// along with no identity injection.
func TestReload_WithRedisExchangeCache_FailsWhenRedisUnavailable(t *testing.T) {
	exchangeSrv := newSuccessExchangeServer(t, "should-not-be-reached")

	cfg := BackendConfig{
		Name:                  "b",
		Type:                  "http",
		URL:                   "http://127.0.0.1:19999/mcp", // unreachable backend — not called
		AllowPrivateAddresses: true,
		UserIdentity: BackendUserIdentity{
			Exchange: BackendIdentityExchange{
				URL: exchangeSrv.URL,
				Cache: BackendIdentityExchangeCache{
					TTL: 300, // TTL > 0 triggers cache construction
				},
			},
		},
	}

	// Point storage at a Redis address that is guaranteed to be unreachable.
	badStorage := cfgloader.StorageConfig{
		Backend: "redis",
		Config:  map[string]any{"addr": "127.0.0.1:19998"},
	}

	r := NewRouter([]BackendConfig{cfg}, badStorage)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := r.Reload(ctx, []BackendConfig{cfg})
	if err == nil {
		t.Fatal("Reload: expected error when Redis is unavailable, got nil")
	}
}
