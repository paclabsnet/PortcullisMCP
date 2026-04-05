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

package gate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// fakeIdentitySource is a minimal IdentitySource for testing single-tenant token fallback.
type fakeIdentitySource struct{ rawToken string }

func (f *fakeIdentitySource) Get(_ context.Context) shared.UserIdentity {
	return shared.UserIdentity{RawToken: f.rawToken}
}
func (f *fakeIdentitySource) SetToken(_ string) error { return nil }
func (f *fakeIdentitySource) Clear()                  {}

// newTestHandler builds an MCPHTTPHandler wired for tests.
func newTestHandler(
	t *testing.T,
	tenancy, authType, tokenHeader string,
	sessions SessionStore,
	identity IdentitySource,
) *MCPHTTPHandler {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "test-gate", Version: "0.0.0"}, nil)
	cfg := Config{
		Tenancy: tenancy,
		Server: cfgloader.ServerConfig{
			Endpoints: map[string]cfgloader.EndpointConfig{
				MCPEndpoint: {
					Auth: cfgloader.AuthSettings{
						Type: authType,
						Credentials: cfgloader.AuthCredentials{
							Header: tokenHeader,
						},
					},
				},
			},
		},
	}
	var provider TenancyProvider
	if tenancy == "multi" {
		provider = NewMultiTenantProvider(tokenHeader, sessions, nil)
	} else {
		provider = NewSingleTenantProvider(identity, tokenHeader)
	}
	return NewMCPHTTPHandler(srv, nil, cfg, provider)
}

// --- health check tests ---

func TestMCPHTTPHealthChecks(t *testing.T) {
	h := newTestHandler(t, "single", "none", "", nil, nil)

	for _, path := range []string{"/healthz", "/readyz"} {
		t.Run(path+" returns 200 OK", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("GET %s: status = %d, want %d", path, rr.Code, http.StatusOK)
			}
			if body := rr.Body.String(); body != "ok" {
				t.Errorf("GET %s: body = %q, want %q", path, body, "ok")
			}
		})

		t.Run(path+" returns 200 OK for POST too", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("POST %s: status = %d, want %d", path, rr.Code, http.StatusOK)
			}
		})
	}

	t.Run("non-health path is not intercepted by health handler", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Body.String() == "ok" {
			t.Error("/mcp should not return the health-check body")
		}
	})
}

// --- middleware tests ---

func TestMCPHTTPMiddleware(t *testing.T) {
	ctx := context.Background()

	t.Run("missing token with auth required returns 401", func(t *testing.T) {
		h := newTestHandler(t, "multi", "bearer", "X-User-Token", NewMemorySessionStore(), nil)
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rr.Code)
		}
	})

	t.Run("auth=none with no token proceeds without 401", func(t *testing.T) {
		h := newTestHandler(t, "multi", "none", "X-User-Token", nil, nil)
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusUnauthorized {
			t.Error("expected no 401 when auth=none")
		}
	})

	t.Run("single-tenant fallback uses global identity token", func(t *testing.T) {
		identity := &fakeIdentitySource{rawToken: "header.payload.sig"}
		h := newTestHandler(t, "single", "bearer", "X-User-Token", NewMemorySessionStore(), identity)
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		// No X-User-Token header — middleware must fall back to identity.Get().RawToken.
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusUnauthorized {
			t.Error("single-tenant: expected fallback to global identity, got 401")
		}
	})

	t.Run("new session is created when no Mcp-Session-Id is provided", func(t *testing.T) {
		store := NewMemorySessionStore()
		h := newTestHandler(t, "multi", "bearer", "X-User-Token", store, nil)
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("X-User-Token", "header.payload.sig")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusUnauthorized || rr.Code == http.StatusForbidden || rr.Code == http.StatusInternalServerError {
			t.Errorf("unexpected error status %d creating new session", rr.Code)
		}
	})

	t.Run("multi-tenant: valid session with matching fingerprint is accepted", func(t *testing.T) {
		store := NewMemorySessionStore()
		token := "header.payload.sig"
		_ = store.SaveSession(ctx, "sess-ok", "", credentialFingerprint(token))

		h := newTestHandler(t, "multi", "bearer", "X-User-Token", store, nil)
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Mcp-Session-Id", "sess-ok")
		req.Header.Set("X-User-Token", token)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusForbidden {
			t.Error("valid fingerprint match should not return 403")
		}
	})

	t.Run("multi-tenant: mismatched fingerprint returns 403", func(t *testing.T) {
		store := NewMemorySessionStore()
		// Register fingerprint for token-A; present token-B.
		_ = store.SaveSession(ctx, "sess-hijack", "", credentialFingerprint("token-A"))

		h := newTestHandler(t, "multi", "bearer", "X-User-Token", store, nil)
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Mcp-Session-Id", "sess-hijack")
		req.Header.Set("X-User-Token", "token-B")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("fingerprint mismatch: status = %d, want 403", rr.Code)
		}
	})

	t.Run("multi-tenant: expired/unknown session generates new session", func(t *testing.T) {
		store := NewMemorySessionStore()
		h := newTestHandler(t, "multi", "bearer", "X-User-Token", store, nil)
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Mcp-Session-Id", "expired-or-unknown")
		req.Header.Set("X-User-Token", "fresh-token")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusForbidden || rr.Code == http.StatusInternalServerError {
			t.Errorf("expired session should trigger new-session flow, got %d", rr.Code)
		}
	})

	t.Run("single-tenant: fingerprint check is skipped", func(t *testing.T) {
		store := NewMemorySessionStore()
		// Store fingerprint for token-A; present token-B — single-tenant bypasses check.
		_ = store.SaveSession(ctx, "sess-single", "", credentialFingerprint("token-A"))

		h := newTestHandler(t, "single", "bearer", "X-User-Token", store, nil)
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Mcp-Session-Id", "sess-single")
		req.Header.Set("X-User-Token", "token-B")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusForbidden {
			t.Error("single-tenant: fingerprint check should be skipped, got 403")
		}
	})

	t.Run("session ID and raw token are injected into request context", func(t *testing.T) {
		var capturedCtx context.Context
		store := NewMemorySessionStore()

		srv := mcp.NewServer(&mcp.Implementation{Name: "cap", Version: "0.0.0"}, nil)
		cfg := Config{
			Tenancy: "multi",
			Server: cfgloader.ServerConfig{
				Endpoints: map[string]cfgloader.EndpointConfig{
					MCPEndpoint: {
						Auth: cfgloader.AuthSettings{
							Type: "bearer",
							Credentials: cfgloader.AuthCredentials{Header: "X-User-Token"},
						},
					},
				},
			},
		}
		h := NewMCPHTTPHandler(srv, nil, cfg, NewMultiTenantProvider("X-User-Token", store, nil))
		// Replace the sdk handler with a capturing stub.
		h.sdkHandler = http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			capturedCtx = r.Context()
		})

		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("X-User-Token", "my.raw.token")
		h.ServeHTTP(httptest.NewRecorder(), req)

		if capturedCtx == nil {
			t.Fatal("sdk handler was not called")
		}
		if sid, ok := SessionIDFromContext(capturedCtx); !ok || sid == "" {
			t.Error("session ID was not injected into context")
		}
		if capturedCtx.Value(identityKey) == nil {
			t.Error("identity (raw token) was not injected into context")
		}
	})
}
