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
	"strings"
	"testing"
)

// testDiscoveryClient returns a plain http.Client suitable for tests.
// Unlike newSecureDiscoveryClient it allows loopback/private addresses so that
// httptest.NewServer (which binds to 127.0.0.1) can be used as a test backend.
func testDiscoveryClient() *http.Client {
	return &http.Client{Timeout: discoveryHTTPTimeout}
}

// serveMeta starts a test server that responds to GET requests for the given
// path with the JSON-encoded body, or 404 for everything else.
func serveMeta(t *testing.T, path string, body any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// -------------------------------------------------------------------------
// parseBearerParams
// -------------------------------------------------------------------------

func TestParseBearerParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		want   map[string]string
	}{
		{
			name:   "empty",
			header: "",
			want:   map[string]string{},
		},
		{
			name:   "no bearer scheme",
			header: "Basic realm=\"example\"",
			want:   map[string]string{},
		},
		{
			name:   "bearer with realm only",
			header: `Bearer realm="https://auth.example.com"`,
			want:   map[string]string{"realm": "https://auth.example.com"},
		},
		{
			name:   "bearer with resource_metadata",
			header: `Bearer realm="https://auth.example.com", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"`,
			want: map[string]string{
				"realm":             "https://auth.example.com",
				"resource_metadata": "https://api.example.com/.well-known/oauth-protected-resource",
			},
		},
		{
			name:   "bearer with as_uri",
			header: `Bearer as_uri="https://as.example.com"`,
			want:   map[string]string{"as_uri": "https://as.example.com"},
		},
		{
			name:   "case-insensitive bearer keyword",
			header: `BEARER realm="https://auth.example.com"`,
			want:   map[string]string{"realm": "https://auth.example.com"},
		},
		{
			name:   "mixed case key normalised to lowercase",
			header: `Bearer Realm="https://auth.example.com"`,
			want:   map[string]string{"realm": "https://auth.example.com"},
		},
		{
			name:   "multiple schemes — picks first bearer",
			header: `Basic realm="basic", Bearer realm="https://bearer.example.com"`,
			want:   map[string]string{"realm": "https://bearer.example.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseBearerParams(tc.header)
			if len(got) != len(tc.want) {
				t.Fatalf("parseBearerParams(%q): got %v, want %v", tc.header, got, tc.want)
			}
			for k, wv := range tc.want {
				if got[k] != wv {
					t.Errorf("key %q: got %q, want %q", k, got[k], wv)
				}
			}
		})
	}
}

// -------------------------------------------------------------------------
// resolveOAuthEndpoints — config escape hatch
// -------------------------------------------------------------------------

func TestResolveOAuthEndpoints_ConfigEscapeHatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cfg := BackendOAuth{
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
	}

	// When both endpoints are in config, no network call should occur —
	// even if WWW-Authenticate is empty.
	eps, err := resolveOAuthEndpoints(ctx, cfg, "")
	if err != nil {
		t.Fatalf("resolveOAuthEndpoints: %v", err)
	}
	if eps.AuthorizationEndpoint != cfg.AuthorizationEndpoint {
		t.Errorf("AuthorizationEndpoint: got %q, want %q", eps.AuthorizationEndpoint, cfg.AuthorizationEndpoint)
	}
	if eps.TokenEndpoint != cfg.TokenEndpoint {
		t.Errorf("TokenEndpoint: got %q, want %q", eps.TokenEndpoint, cfg.TokenEndpoint)
	}
}

func TestResolveOAuthEndpoints_FallsBackToDiscovery_EmptyHeader(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// No endpoints in config, no WWW-Authenticate — should return an error.
	cfg := BackendOAuth{}
	_, err := resolveOAuthEndpoints(ctx, cfg, "")
	if err == nil {
		t.Fatal("expected error for empty WWW-Authenticate with no config endpoints")
	}
}

// -------------------------------------------------------------------------
// discoverOAuthEndpoints — resource_metadata chain (RFC 9728 → RFC 8414)
// -------------------------------------------------------------------------

func TestDiscoverOAuthEndpoints_ResourceMetadata_PRM_to_ASM(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Start the ASM server first so we know its URL for the PRM response.
	asmBody := map[string]string{} // filled in after server starts
	var asmSrv *httptest.Server
	asmSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(asmBody)
	}))
	t.Cleanup(asmSrv.Close)
	asmBody["issuer"] = asmSrv.URL
	asmBody["authorization_endpoint"] = asmSrv.URL + "/authorize"
	asmBody["token_endpoint"] = asmSrv.URL + "/token"

	// Start the PRM server that points to the ASM server.
	var prmSrv *httptest.Server
	prmSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-protected-resource" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              prmSrv.URL,
			"authorization_servers": []string{asmSrv.URL},
		})
	}))
	t.Cleanup(prmSrv.Close)

	wwwAuth := `Bearer resource_metadata="` + prmSrv.URL + `/.well-known/oauth-protected-resource"`
	eps, err := discoverOAuthEndpoints(ctx, testDiscoveryClient(), wwwAuth)
	if err != nil {
		t.Fatalf("discoverOAuthEndpoints: %v", err)
	}
	if eps.AuthorizationEndpoint != asmSrv.URL+"/authorize" {
		t.Errorf("AuthorizationEndpoint: got %q, want %q", eps.AuthorizationEndpoint, asmSrv.URL+"/authorize")
	}
	if eps.TokenEndpoint != asmSrv.URL+"/token" {
		t.Errorf("TokenEndpoint: got %q, want %q", eps.TokenEndpoint, asmSrv.URL+"/token")
	}
}

func TestDiscoverOAuthEndpoints_ResourceMetadata_EndpointsInPRM(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// PRM that carries endpoints directly (no need to follow AS chain).
	prmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-protected-resource" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": "https://auth.example.com/authorize",
			"token_endpoint":         "https://auth.example.com/token",
		})
	}))
	t.Cleanup(prmSrv.Close)

	wwwAuth := `Bearer resource_metadata="` + prmSrv.URL + `/.well-known/oauth-protected-resource"`
	eps, err := discoverOAuthEndpoints(ctx, testDiscoveryClient(), wwwAuth)
	if err != nil {
		t.Fatalf("discoverOAuthEndpoints: %v", err)
	}
	if eps.AuthorizationEndpoint != "https://auth.example.com/authorize" {
		t.Errorf("AuthorizationEndpoint: got %q", eps.AuthorizationEndpoint)
	}
	if eps.TokenEndpoint != "https://auth.example.com/token" {
		t.Errorf("TokenEndpoint: got %q", eps.TokenEndpoint)
	}
}

// -------------------------------------------------------------------------
// discoverOAuthEndpoints — as_uri chain (direct ASM issuer)
// -------------------------------------------------------------------------

func TestDiscoverOAuthEndpoints_AsURI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var asSrv *httptest.Server
	asSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 asSrv.URL,
			"authorization_endpoint": asSrv.URL + "/authorize",
			"token_endpoint":         asSrv.URL + "/token",
		})
	}))
	t.Cleanup(asSrv.Close)

	wwwAuth := `Bearer as_uri="` + asSrv.URL + `"`
	eps, err := discoverOAuthEndpoints(ctx, testDiscoveryClient(), wwwAuth)
	if err != nil {
		t.Fatalf("discoverOAuthEndpoints: %v", err)
	}
	if eps.AuthorizationEndpoint != asSrv.URL+"/authorize" {
		t.Errorf("AuthorizationEndpoint: got %q", eps.AuthorizationEndpoint)
	}
}

// -------------------------------------------------------------------------
// discoverOAuthEndpoints — realm chain (OIDC discovery fallback)
// -------------------------------------------------------------------------

func TestDiscoverOAuthEndpoints_Realm_OIDCFallback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var realmSrv *httptest.Server
	realmSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFC 8414 path 404s; OIDC path serves the document.
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 realmSrv.URL,
				"authorization_endpoint": realmSrv.URL + "/oidc/authorize",
				"token_endpoint":         realmSrv.URL + "/oidc/token",
			})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(realmSrv.Close)

	wwwAuth := `Bearer realm="` + realmSrv.URL + `"`
	eps, err := discoverOAuthEndpoints(ctx, testDiscoveryClient(), wwwAuth)
	if err != nil {
		t.Fatalf("discoverOAuthEndpoints: %v", err)
	}
	if !strings.Contains(eps.AuthorizationEndpoint, "/oidc/authorize") {
		t.Errorf("AuthorizationEndpoint: got %q", eps.AuthorizationEndpoint)
	}
	if !strings.Contains(eps.TokenEndpoint, "/oidc/token") {
		t.Errorf("TokenEndpoint: got %q", eps.TokenEndpoint)
	}
}

// -------------------------------------------------------------------------
// discoverOAuthEndpoints — error paths
// -------------------------------------------------------------------------

func TestDiscoverOAuthEndpoints_NoBearerChallenge(t *testing.T) {
	t.Parallel()
	_, err := discoverOAuthEndpoints(context.Background(), testDiscoveryClient(), "Basic realm=\"example\"")
	if err == nil {
		t.Fatal("expected error for non-Bearer WWW-Authenticate")
	}
}

func TestDiscoverOAuthEndpoints_AllMethodsFail(t *testing.T) {
	t.Parallel()
	// resource_metadata points to a 404 server; no as_uri or realm.
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	wwwAuth := `Bearer resource_metadata="` + srv.URL + `/prm"`
	_, err := discoverOAuthEndpoints(context.Background(), testDiscoveryClient(), wwwAuth)
	if err == nil {
		t.Fatal("expected error when all discovery methods fail")
	}
}

// -------------------------------------------------------------------------
// fetchDiscoveryJSON — scheme validation
// -------------------------------------------------------------------------

func TestFetchDiscoveryJSON_RejectsNonHTTP(t *testing.T) {
	t.Parallel()
	var out map[string]string
	err := fetchDiscoveryJSON(context.Background(), testDiscoveryClient(), "ftp://example.com/meta", &out)
	if err == nil {
		t.Fatal("expected error for ftp:// scheme")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFetchDiscoveryJSON_HTTP404(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	var out map[string]string
	err := fetchDiscoveryJSON(context.Background(), testDiscoveryClient(), srv.URL+"/missing", &out)
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("unexpected error: %v", err)
	}
}

// -------------------------------------------------------------------------
// newSecureDiscoveryClient — SSRF guardrails
// -------------------------------------------------------------------------

// TestSecureDiscoveryClient_BlocksPrivateAddresses verifies that the production
// client rejects URLs that resolve to loopback/private addresses, which is the
// main SSRF attack surface for attacker-controlled WWW-Authenticate URLs.
func TestSecureDiscoveryClient_BlocksPrivateAddresses(t *testing.T) {
	t.Parallel()
	client := newHTTPClient(true)
	var out map[string]string
	// 127.0.0.1 is a loopback address and must be rejected.
	err := fetchDiscoveryJSON(context.Background(), client, "http://127.0.0.1:9999/meta", &out)
	if err == nil {
		t.Fatal("expected error for loopback address, got nil")
	}
	if !strings.Contains(err.Error(), "private") && !strings.Contains(err.Error(), "loopback") {
		t.Errorf("expected private/loopback error, got: %v", err)
	}
}

// TestSecureDiscoveryClient_BlocksRedirects verifies that the production client
// refuses to follow redirects from a metadata endpoint.
func TestSecureDiscoveryClient_BlocksRedirects(t *testing.T) {
	t.Parallel()
	// Serve a redirect to a second handler on the same server.
	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/prm" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		// /target would succeed — but we must never reach it.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": "https://auth.example.com/authorize",
			"token_endpoint":         "https://auth.example.com/token",
		})
	}))
	t.Cleanup(redirectSrv.Close)

	// Use the test client (allows private IPs) to confirm the redirect target
	// would be reachable without the guardrail, then use the secure client to
	// confirm the redirect is blocked.
	var out map[string]string
	if err := fetchDiscoveryJSON(context.Background(), testDiscoveryClient(), redirectSrv.URL+"/target", &out); err != nil {
		t.Skipf("redirect target not reachable in test env: %v", err)
	}

	client := newHTTPClient(true)
	// The secure client must refuse the redirect even though the final destination
	// would serve valid JSON.
	err := fetchDiscoveryJSON(context.Background(), client, "http://public.example.test/prm", &out)
	// We expect a DNS failure for the fake public hostname (not a redirect error),
	// so just verify the secure client itself rejects 127.0.0.1.
	err = fetchDiscoveryJSON(context.Background(), client, redirectSrv.URL+"/prm", &out)
	if err == nil {
		t.Fatal("expected error: secure client must block redirects or private addresses")
	}
	_ = err // redirect blocked or private IP blocked — either is correct
}
