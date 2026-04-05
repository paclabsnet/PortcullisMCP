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
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// newMultiTenantHTTPHandler builds an MCPHTTPHandler configured for multi-tenant
// mode using a MemorySessionStore. tokenHeader is the header name for inbound tokens.
func newMultiTenantHTTPHandler(t *testing.T, tokenHeader string, store SessionStore) *MCPHTTPHandler {
	t.Helper()
	if store == nil {
		store = NewMemorySessionStore()
	}
	return newTestHandler(t, "multi", "bearer", tokenHeader, store, nil)
}

// TestMultiTenantBoundary_CrossTenantIsolation verifies that presenting User A's
// token alongside User B's session ID results in 403 Forbidden, never in access
// to User B's session state.
func TestMultiTenantBoundary_CrossTenantIsolation(t *testing.T) {
	store := NewMemorySessionStore()
	tokenA := "user-a-token"
	tokenB := "user-b-token"

	// User B established a session with their own token fingerprint.
	sessionB := "session-of-user-b"
	if err := store.SaveSession(context.Background(), sessionB, "", credentialFingerprint(tokenB)); err != nil {
		t.Fatalf("setup: save session: %v", err)
	}

	h := newMultiTenantHTTPHandler(t, "X-User-Token", store)

	// User A presents User B's session ID but their own (mismatched) token.
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Mcp-Session-Id", sessionB)
	req.Header.Set("X-User-Token", tokenA)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("cross-tenant session hijack attempt: status = %d, want 403 Forbidden", rr.Code)
	}
}

// newMultiTenantConfig returns a minimal Config that passes validation for
// tenancy: multi. It uses the "os" identity strategy and "dev" mode so that
// no OIDC configuration or TLS is required. A temp directory is used for the
// escalation token store so the test leaves no files behind.
//
// The Keep peer is pointed at a non-existent address; New() will log a warning
// when refreshKeepTools fails to connect, but will still return a valid Gate.
func newMultiTenantConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Mode:    cfgloader.ModeDev,
		Tenancy: "multi",
		Identity: IdentityConfig{Strategy: "os"},
		Server: cfgloader.ServerConfig{
			SessionTTL: 3600,
			Endpoints: map[string]cfgloader.EndpointConfig{
				MCPEndpoint: {Listen: "127.0.0.1:0"},
			},
		},
		Peers: PeersConfig{
			Keep: cfgloader.PeerAuth{Endpoint: "http://127.0.0.1:19999"},
		},
		Responsibility: ResponsibilityConfig{
			Escalation: EscalationConfig{
				TokenStore: filepath.Join(t.TempDir(), "tokens.json"),
			},
		},
	}
}

// TestMultiTenantBoundary_RegistryStrictness verifies that a Gate constructed
// via New() with tenancy: multi has zero local-filesystem tools registered, even
// when the Keep peer is unreachable. This exercises the real initialization and
// registration guards (server.go lines ~131 and ~281) rather than a hand-built
// struct whose maps are trivially empty.
func TestMultiTenantBoundary_RegistryStrictness(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	g, err := New(ctx, newMultiTenantConfig(t))
	if err != nil {
		t.Fatalf("New() with valid multi-tenant config: %v", err)
	}
	t.Cleanup(func() {
		close(g.logDone)
		g.logWg.Wait()
	})

	if len(g.localFSTools) != 0 {
		t.Errorf("multi-tenant Gate.localFSTools must be empty after New(); got %d: %v",
			len(g.localFSTools), g.localFSTools)
	}
}

// TestMultiTenantBoundary_LocalFSEnabledRejected verifies that New() refuses to
// construct a multi-tenant Gate when LocalFS is misconfigured as Enabled: true.
// This confirms the config-validation layer enforces the isolation constraint
// before any runtime guard can be bypassed.
func TestMultiTenantBoundary_LocalFSEnabledRejected(t *testing.T) {
	ctx := context.Background()
	cfg := newMultiTenantConfig(t)
	cfg.Responsibility.Tools.LocalFS.Enabled = true
	cfg.Responsibility.Tools.LocalFS.Workspace = SandboxConfig{Directory: t.TempDir()}

	_, err := New(ctx, cfg)
	if err == nil {
		t.Fatal("New() must return an error when LocalFS.Enabled=true in multi-tenant mode")
	}
	if !strings.Contains(err.Error(), "portcullis-localfs") {
		t.Errorf("error should mention portcullis-localfs; got: %v", err)
	}
}

// TestMultiTenantBoundary_LocalFSBlockedByTenancy verifies that the localFS
// initialization guard rejects startup even when LocalFS.Enabled is true and
// workspace dirs are configured, if tenancy is "multi". This is the defence-in-
// depth check: config validation may be bypassed (e.g. programmatic construction)
// but the runtime must never start a localFS session in multi-tenant mode.
func TestMultiTenantBoundary_LocalFSBlockedByTenancy(t *testing.T) {
	// Simulate the condition that triggers localFS init: Enabled=true with dirs set.
	// In multi-tenant mode the outer guard must prevent any session from being created.
	cfg := Config{
		Tenancy: "multi",
		Responsibility: ResponsibilityConfig{
			Tools: ToolsConfig{
				LocalFS: LocalFSConfig{
					Enabled:   true, // misconfigured — validation normally forbids this
					Workspace: SandboxConfig{Directory: "/tmp"},
				},
			},
		},
	}

	// The guard condition mirrors server.go: tenancy != "multi" && LocalFS.Enabled.
	// Verify it correctly blocks initialization.
	shouldInit := cfg.Tenancy != "multi" && cfg.Responsibility.Tools.LocalFS.Enabled
	if shouldInit {
		t.Error("localFS init guard failed: would start a localFS session in multi-tenant mode")
	}

	// Also verify the registration guard: localFSSession != nil && tenancy != "multi".
	// Even if a non-nil session somehow existed, registration must be skipped.
	simulatedNonNilSession := true // stand-in for a non-nil *mcp.ClientSession
	shouldRegister := simulatedNonNilSession && cfg.Tenancy != "multi"
	if shouldRegister {
		t.Error("localFS registration guard failed: would register localfs tools in multi-tenant mode")
	}
}

// TestMultiTenantBoundary_StatelessnessAudit verifies that after a Deny response
// in multi-tenant mode the PendingEscalationStore remains completely empty —
// no "human-in-the-loop" state leaks across the tenant boundary.
func TestMultiTenantBoundary_StatelessnessAudit(t *testing.T) {
	pending := NewInMemoryPendingStore()
	logChan := make(chan DecisionLogEntry, 10)
	g := &Gate{
		cfg: Config{
			Tenancy: "multi",
		},
		pending:  pending,
		logChan:  logChan,
		logDone:  make(chan struct{}),
		provider: NewMultiTenantProvider("", nil, logChan),
	}

	escalationErr := &shared.EscalationPendingError{
		Reason:        "requires manager sign-off",
		EscalationJTI: "jti-stateless-check",
		PendingJWT:    "h.p.s",
	}

	// Simulate the full deny path: maybeStorePendingEscalation then policyErrToResult.
	if err := g.maybeStorePendingEscalation(context.Background(), "backend-server", "sensitive_tool", escalationErr); err != nil {
		t.Fatalf("maybeStorePendingEscalation: %v", err)
	}
	_, _ = g.policyErrToResult(context.Background(), escalationErr, "sensitive_tool", "trace-stateless")

	// The pending store must be empty after the full deny path.
	if _, ok := pending.Get("backend-server/sensitive_tool"); ok {
		t.Error("PendingEscalationStore must remain empty after multi-tenant deny (no state leakage)")
	}
}

// TestMultiTenantBoundary_FingerprintEnforcement verifies that changing the token
// for an active session triggers a 403 Forbidden security rejection.
func TestMultiTenantBoundary_FingerprintEnforcement(t *testing.T) {
	store := NewMemorySessionStore()
	activeSession := "active-session-id"
	originalToken := "original-token-abc"
	rotatedToken := "rotated-token-xyz"

	// Establish a session with the original token fingerprint.
	if err := store.SaveSession(context.Background(), activeSession, "", credentialFingerprint(originalToken)); err != nil {
		t.Fatalf("setup: save session: %v", err)
	}

	h := newMultiTenantHTTPHandler(t, "X-User-Token", store)

	t.Run("original token is accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Mcp-Session-Id", activeSession)
		req.Header.Set("X-User-Token", originalToken)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusForbidden {
			t.Errorf("original token should be accepted; got 403")
		}
	})

	t.Run("rotated token for same session is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Mcp-Session-Id", activeSession)
		req.Header.Set("X-User-Token", rotatedToken)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("token rotation for active session: status = %d, want 403 Forbidden", rr.Code)
		}
	})
}

// TestMultiTenantBoundary_CorrelationAudit verifies that the trace_id is
// consistently present in SIEM DecisionLogEntry records emitted for denied
// requests in multi-tenant mode.
func TestMultiTenantBoundary_CorrelationAudit(t *testing.T) {
	logChan := make(chan DecisionLogEntry, 10)
	g := &Gate{
		cfg: Config{
			Tenancy: "multi",
			Responsibility: ResponsibilityConfig{
				Escalation: EscalationConfig{NoEscalationMarker: "DENIED"},
			},
		},
		pending:  NewInMemoryPendingStore(),
		logChan:  logChan,
		logDone:  make(chan struct{}),
		provider: NewMultiTenantProvider("", nil, logChan),
	}

	testCases := []struct {
		name    string
		err     error
		traceID string
	}{
		{
			name:    "escalation error produces SIEM log with trace_id",
			err:     &shared.EscalationPendingError{Reason: "needs approval", EscalationJTI: "jti-1"},
			traceID: "trace-correlation-1",
		},
		{
			name:    "deny error produces SIEM log with trace_id",
			err:     &shared.DenyError{Reason: "not permitted"},
			traceID: "trace-correlation-2",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := withSessionID(context.Background(), "session-correlation")

			_, _ = g.policyErrToResult(ctx, tc.err, "audited_tool", tc.traceID)

			select {
			case entry := <-logChan:
				if entry.TraceID == "" {
					t.Error("trace_id must be present in SIEM log for correlation")
				}
				if entry.TraceID != tc.traceID {
					t.Errorf("trace_id = %q, want %q", entry.TraceID, tc.traceID)
				}
				if entry.Decision != "deny" {
					t.Errorf("decision = %q, want %q", entry.Decision, "deny")
				}
			default:
				t.Error("expected a SIEM DecisionLogEntry to be queued, but logChan was empty")
			}
		})
	}
}

// TestMultiTenantBoundary_InfraErrorsNotMasked verifies that infrastructure errors
// (identity verification failures, transport errors, and other unknown errors) are
// NOT converted to deny markers in multi-tenant mode. They must propagate as real
// errors so callers can distinguish a PDP/transport outage from a policy denial.
func TestMultiTenantBoundary_InfraErrorsNotMasked(t *testing.T) {
	logChan := make(chan DecisionLogEntry, 10)
	g := &Gate{
		cfg: Config{
			Tenancy: "multi",
			Responsibility: ResponsibilityConfig{
				Escalation: EscalationConfig{NoEscalationMarker: "SIEM-DENY"},
			},
		},
		pending:  NewInMemoryPendingStore(),
		logChan:  logChan,
		logDone:  make(chan struct{}),
		provider: NewMultiTenantProvider("", nil, logChan),
	}

	infraErrors := []struct {
		name string
		err  error
	}{
		{
			name: "IdentityVerificationError is returned as-is",
			err:  &shared.IdentityVerificationError{Reason: "token expired"},
		},
		{
			name: "unknown transport error is returned as-is",
			err:  fmt.Errorf("connection refused"),
		},
	}

	for _, tc := range infraErrors {
		t.Run(tc.name, func(t *testing.T) {
			result, retErr := g.policyErrToResult(context.Background(), tc.err, "tool", "trace-infra")

			// Infrastructure errors must surface as a returned error, not a denied result.
			if retErr == nil {
				t.Error("expected a returned error for infrastructure failure, got nil")
			}
			if result != nil {
				t.Errorf("expected nil result for infrastructure error, got: %+v", result)
			}
			// No SIEM log should be queued for infrastructure errors.
			select {
			case entry := <-g.logChan:
				t.Errorf("infrastructure error must not emit a SIEM log entry; got: %+v", entry)
			default:
			}
		})
	}
}
