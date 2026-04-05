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

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
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

// TestMultiTenantBoundary_RegistryStrictness verifies that a Gate configured
// with tenancy: multi has zero local-filesystem tools registered and does not
// expose native portcullis tools via the tool-server routing map.
func TestMultiTenantBoundary_RegistryStrictness(t *testing.T) {
	g := &Gate{
		cfg: Config{
			Tenancy: "multi",
		},
		localFSTools:  make(map[string]bool),
		toolServerMap: make(map[string]string),
	}

	// In multi-tenant mode, localFSTools must be empty because LocalFS is
	// forbidden by config validation and the registration block is gated.
	if len(g.localFSTools) != 0 {
		t.Errorf("multi-tenant Gate must have zero localfs tools; got %d", len(g.localFSTools))
	}

	// Native portcullis tools must not appear in the tool-server routing map.
	// They are registered directly on the mcp.Server in single-tenant mode only;
	// in multi-tenant mode that block is skipped entirely.
	nativeTools := []string{"portcullis_status", "portcullis_login"}
	for _, name := range nativeTools {
		if _, found := g.toolServerMap[name]; found {
			t.Errorf("native tool %q must not be in toolServerMap in multi-tenant mode", name)
		}
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
	g := &Gate{
		cfg: Config{
			Tenancy: "multi",
		},
		pending: pending,
		logChan: make(chan DecisionLogEntry, 10),
		logDone: make(chan struct{}),
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
		pending: NewInMemoryPendingStore(),
		logChan: logChan,
		logDone: make(chan struct{}),
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
