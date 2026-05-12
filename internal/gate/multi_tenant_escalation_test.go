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
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// ---- Step 1: Guard unavailable → "Authorization system unavailable" ----------

// TestEscalation_GuardUnavailable_ProactiveDependency verifies that when Guard
// is unreachable during StorePending, the resulting error is a
// *GuardUnavailableError and that policyErrToResult converts it to the
// canonical "Authorization system unavailable" agent message.
func TestEscalation_GuardUnavailable_ProactiveDependency(t *testing.T) {
	guard := &mockGuardClient{
		registerPendingFunc: func(_ context.Context, _, _ string) error {
			return fmt.Errorf("connection refused")
		},
	}
	pending := NewInMemoryPendingStore()
	mgr := NewEscalationManager(guard, pending, &mockTokenStore{}, EscalationConfig{},
		NewSingleTenantProvider(nil, ""), nil, "session")

	escalationErr := &shared.EscalationPendingError{
		Reason:        "needs manager approval",
		EscalationJTI: "jti-unavail-test",
		PendingJWT:    "h.p.s",
	}

	storeErr := mgr.StorePending(context.Background(), "backend", "sensitive_tool", escalationErr)
	if storeErr == nil {
		t.Fatal("StorePending must return an error when Guard is unreachable")
	}

	var guardErr *GuardUnavailableError
	if !errors.As(storeErr, &guardErr) {
		t.Fatalf("expected *GuardUnavailableError, got %T: %v", storeErr, storeErr)
	}
	if guardErr.JTI != "jti-unavail-test" {
		t.Errorf("GuardUnavailableError.JTI = %q, want %q", guardErr.JTI, "jti-unavail-test")
	}

	// The pending store must remain empty — no state recorded when Guard is down.
	if _, ok := pending.Get(context.Background(), "backend/sensitive_tool"); ok {
		t.Error("pending store must be empty when Guard registration fails")
	}

	// policyErrToResult must convert GuardUnavailableError to a user-facing message.
	g := &Gate{
		cfg: Config{
			Escalation: "session",
			Peers: PeersConfig{
				Guard: GateSpecificGuardConfig{
					GuardPeerConfig: cfgloader.GuardPeerConfig{
						Endpoints: cfgloader.GuardEndpoints{ApprovalUI: "http://guard.example.com"},
					},
				},
			},
		},
		provider: NewSingleTenantProvider(nil, ""),
	}

	result, retErr := g.policyErrToResult(context.Background(), storeErr, "sensitive_tool", "trace-unavail")
	if retErr != nil {
		t.Fatalf("policyErrToResult returned unexpected error: %v", retErr)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected an error CallToolResult")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected *mcp.TextContent, got %T", result.Content[0])
	}
	if !strings.Contains(tc.Text, "Authorization system unavailable") {
		t.Errorf("message should contain 'Authorization system unavailable'; got: %s", tc.Text)
	}
}

// TestEscalation_GuardUnavailable_GuardAPIError verifies that a *GuardAPIError
// returned by ClaimToken during CollectTokens does not crash or leak state —
// it is logged and the original token list is returned unchanged.
func TestEscalation_GuardUnavailable_GuardAPIError(t *testing.T) {
	pending := NewInMemoryPendingStore()
	// Pre-populate a pending escalation so ClaimToken is attempted.
	ctx := withSessionID(context.Background(), "sess-api-err")
	key := "sess:sess-api-err:backend/tool"
	pending.Store(ctx, key, pendingEscalation{
		ServerName: "backend",
		ToolName:   "tool",
		JTI:        "jti-api-err",
		ExpiresAt:  futureTime(),
	})

	guard := &mockGuardClient{
		claimTokenFunc: func(_ context.Context, _ string) (string, error) {
			return "", &GuardAPIError{StatusCode: 503, Err: fmt.Errorf("service unavailable")}
		},
	}

	tokens := &mockTokenStore{
		tokens: []shared.EscalationToken{{TokenID: "existing-tok"}},
	}
	mgr := NewEscalationManager(guard, pending, tokens, EscalationConfig{},
		NewSingleTenantProvider(nil, ""), nil, "session")

	result := mgr.CollectTokens(ctx, "backend", "tool")

	// Original tokens returned unchanged; no panic or empty slice.
	if len(result) != 1 || result[0].TokenID != "existing-tok" {
		t.Errorf("CollectTokens should return existing tokens on GuardAPIError; got %v", result)
	}
}

// ---- Step 2: Full escalation flow in session scope --------------------------

// TestEscalation_FullFlow_SessionScope simulates the complete lazy-claim cycle
// in session-scoped mode:
//
//  1. First call: tool returns EscalationPendingError; StorePending registers
//     with Guard and stores the pending JTI; policyErrToResult returns a URL
//     containing the JTI in ?jti= format.
//  2. Second call (Agent retry): CollectTokens finds the pending JTI, calls
//     ClaimToken which returns an approved escalation JWT, stores the token,
//     removes the pending record, and returns the token list.
func TestEscalation_FullFlow_SessionScope(t *testing.T) {
	const (
		jti       = "flow-jti-session-001"
		sessionID = "agent-session-flow"
		serverName = "keep-backend"
		toolName   = "restricted_op"
		approvalUI = "http://guard.example.com"
	)

	// Build a raw JWT for the approved token (signature is a dummy; store
	// does not verify it — same approach as tokenstore_test.go).
	rawToken := makeTestJWT(map[string]any{
		"jti": jti,
		"exp": futureExp(),
		"granted_by": "manager@corp.com",
	})

	// Guard mock: accepts RegisterPending, returns the raw token on ClaimToken.
	var registeredJTI string
	guard := &mockGuardClient{
		registerPendingFunc: func(_ context.Context, j, _ string) error {
			registeredJTI = j
			return nil
		},
		claimTokenFunc: func(_ context.Context, j string) (string, error) {
			if j == jti {
				return rawToken, nil
			}
			return "", nil
		},
	}

	pending := NewInMemoryPendingStore()
	tokenStore := NewInMemoryTokenStore()
	mgr := NewEscalationManager(guard, pending, tokenStore, EscalationConfig{},
		NewSingleTenantProvider(nil, ""), nil, "session")

	ctx := withSessionID(context.Background(), sessionID)

	// --- Phase 1: first tool call → escalation error ---

	escalationErr := &shared.EscalationPendingError{
		Reason:        "manager sign-off required",
		EscalationJTI: jti,
		PendingJWT:    "pending.jwt.data",
	}

	storeErr := mgr.StorePending(ctx, serverName, toolName, escalationErr)
	if storeErr != nil {
		t.Fatalf("StorePending phase 1: unexpected error: %v", storeErr)
	}
	if registeredJTI != jti {
		t.Errorf("Guard.RegisterPending called with jti=%q, want %q", registeredJTI, jti)
	}

	// Verify pending entry was recorded under the session-scoped key.
	pendingKey := "sess:" + sessionID + ":" + serverName + "/" + toolName
	p, ok := pending.Get(ctx, pendingKey)
	if !ok {
		t.Fatalf("pending escalation not found at key %q", pendingKey)
	}
	if p.JTI != jti {
		t.Errorf("pending.JTI = %q, want %q", p.JTI, jti)
	}

	// policyErrToResult must return a URL with ?jti= pointing at Guard.
	g := &Gate{
		cfg: Config{
			Escalation: "session",
			Peers: PeersConfig{
				Guard: GateSpecificGuardConfig{
					GuardPeerConfig: cfgloader.GuardPeerConfig{
						Endpoints: cfgloader.GuardEndpoints{ApprovalUI: approvalUI},
					},
				},
			},
		},
		provider: NewSingleTenantProvider(nil, ""),
	}

	result, retErr := g.policyErrToResult(ctx, escalationErr, toolName, "trace-flow-1")
	if retErr != nil {
		t.Fatalf("policyErrToResult phase 1: unexpected error: %v", retErr)
	}
	if result == nil || !result.IsError {
		t.Fatal("phase 1: expected error CallToolResult")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("phase 1: expected *mcp.TextContent, got %T", result.Content[0])
	}
	if !strings.Contains(tc.Text, "?jti="+jti) {
		t.Errorf("phase 1: message should contain ?jti=%s; got: %s", jti, tc.Text)
	}
	if !strings.Contains(tc.Text, approvalUI) {
		t.Errorf("phase 1: message should contain Guard approval UI URL; got: %s", tc.Text)
	}

	// --- Phase 2: Agent retry → lazy claim succeeds ---

	tokens := mgr.CollectTokens(ctx, serverName, toolName)
	if len(tokens) != 1 {
		t.Fatalf("phase 2: expected 1 claimed token, got %d", len(tokens))
	}
	if tokens[0].TokenID != jti {
		t.Errorf("phase 2: token.TokenID = %q, want %q", tokens[0].TokenID, jti)
	}

	// Pending record must be cleared after a successful claim.
	if _, ok := pending.Get(ctx, pendingKey); ok {
		t.Error("phase 2: pending record should be deleted after successful claim")
	}
}

// TestEscalation_FullFlow_NotYetApproved verifies that when the Agent retries
// before the approver has acted, CollectTokens returns an empty token list and
// leaves the pending record intact for the next retry.
func TestEscalation_FullFlow_NotYetApproved(t *testing.T) {
	const (
		jti       = "flow-jti-pending-002"
		sessionID = "agent-session-pending"
	)

	guard := &mockGuardClient{
		registerPendingFunc: func(_ context.Context, _, _ string) error { return nil },
		claimTokenFunc: func(_ context.Context, _ string) (string, error) {
			return "", nil // not yet approved
		},
	}

	pending := NewInMemoryPendingStore()
	mgr := NewEscalationManager(guard, pending, &mockTokenStore{}, EscalationConfig{},
		NewSingleTenantProvider(nil, ""), nil, "session")

	ctx := withSessionID(context.Background(), sessionID)

	escalationErr := &shared.EscalationPendingError{
		EscalationJTI: jti,
		PendingJWT:    "h.p.s",
	}
	if err := mgr.StorePending(ctx, "srv", "tool", escalationErr); err != nil {
		t.Fatalf("StorePending: %v", err)
	}

	tokens := mgr.CollectTokens(ctx, "srv", "tool")
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens before approval, got %d", len(tokens))
	}

	// Pending record must still be present for the next retry.
	pendingKey := "sess:" + sessionID + ":srv/tool"
	if _, ok := pending.Get(ctx, pendingKey); !ok {
		t.Error("pending record must survive a not-yet-approved claim attempt")
	}
}

// TestEscalation_FullFlow_FingerprintScope verifies that in fingerprint scope
// the storage key is partitioned by credential fingerprint rather than session.
func TestEscalation_FullFlow_FingerprintScope(t *testing.T) {
	const (
		jti         = "flow-jti-fp-003"
		fingerprint = "abc123fingerprint"
	)

	rawToken := makeTestJWT(map[string]any{
		"jti": jti,
		"exp": futureExp(),
	})

	guard := &mockGuardClient{
		registerPendingFunc: func(_ context.Context, _, _ string) error { return nil },
		claimTokenFunc: func(_ context.Context, j string) (string, error) {
			if j == jti {
				return rawToken, nil
			}
			return "", nil
		},
	}

	pending := NewInMemoryPendingStore()
	tokenStore := NewInMemoryTokenStore()
	mgr := NewEscalationManager(guard, pending, tokenStore, EscalationConfig{},
		NewSingleTenantProvider(nil, ""), nil, "fingerprint")

	ctx := withCredentialFingerprint(context.Background(), fingerprint)

	escalationErr := &shared.EscalationPendingError{
		EscalationJTI: jti,
		PendingJWT:    "h.p.s",
	}
	if err := mgr.StorePending(ctx, "srv", "tool", escalationErr); err != nil {
		t.Fatalf("StorePending: %v", err)
	}

	// Verify the key uses the fingerprint prefix.
	fpKey := "fp:" + fingerprint + ":srv/tool"
	if _, ok := pending.Get(ctx, fpKey); !ok {
		t.Errorf("pending record not found at fingerprint-scoped key %q", fpKey)
	}

	// CollectTokens claims the token using the same fingerprint context.
	tokens := mgr.CollectTokens(ctx, "srv", "tool")
	if len(tokens) != 1 || tokens[0].TokenID != jti {
		t.Errorf("expected 1 claimed token with jti=%q, got %v", jti, tokens)
	}

	// Pending record cleared after claim.
	if _, ok := pending.Get(ctx, fpKey); ok {
		t.Error("pending record should be deleted after successful fingerprint-scoped claim")
	}
}

// futureTime returns a time.Time one hour in the future, used to set
// pendingEscalation.ExpiresAt in tests that pre-populate the pending store.
func futureTime() time.Time {
	return time.Now().Add(time.Hour)
}

// ---- GuardUnavailableError ---------------------------------------------------

func TestGuardUnavailableError_Error(t *testing.T) {
	err := &GuardUnavailableError{JTI: "jti-abc", Err: fmt.Errorf("connection refused")}
	msg := err.Error()
	if !strings.Contains(msg, "jti-abc") {
		t.Errorf("error message should contain JTI; got: %s", msg)
	}
	if !strings.Contains(msg, "connection refused") {
		t.Errorf("error message should contain wrapped error; got: %s", msg)
	}
}

// ---- resolveStoragePrefix edge cases ----------------------------------------

func TestResolveStoragePrefix_SessionNoIDReturnsEmpty(t *testing.T) {
	// No session ID in context → prefix is "" (no partitioning possible).
	result := resolveStoragePrefix(context.Background(), "session", nil)
	if result != "" {
		t.Errorf("expected empty prefix without session ID, got %q", result)
	}
}

func TestResolveStoragePrefix_FingerprintIdentityFallback(t *testing.T) {
	// No fingerprint in ctx, but identity.Get returns a UserID → fall back to UserID.
	identity := &mockIdentitySource{identity: shared.UserIdentity{UserID: "alice@corp.com"}}
	result := resolveStoragePrefix(context.Background(), "fingerprint", identity)
	if result != "fp:alice@corp.com" {
		t.Errorf("expected fingerprint fallback to UserID, got %q", result)
	}
}

func TestResolveStoragePrefix_FingerprintInContextWinsOverIdentity(t *testing.T) {
	ctx := withCredentialFingerprint(context.Background(), "ctx-fingerprint")
	identity := &mockIdentitySource{identity: shared.UserIdentity{UserID: "alice@corp.com"}}
	result := resolveStoragePrefix(ctx, "fingerprint", identity)
	if result != "fp:ctx-fingerprint" {
		t.Errorf("context fingerprint should win over identity fallback, got %q", result)
	}
}

func TestResolveStoragePrefix_UnknownScopeReturnsEmpty(t *testing.T) {
	ctx := withSessionID(context.Background(), "some-session")
	result := resolveStoragePrefix(ctx, "unknown", nil)
	if result != "" {
		t.Errorf("unknown scope should return empty prefix, got %q", result)
	}
}

// ---- InMemoryTokenStore.Delete ----------------------------------------------

func TestInMemoryTokenStore_Delete_Existing(t *testing.T) {
	s := NewInMemoryTokenStore()
	ctx := context.Background()

	raw := makeTestJWT(map[string]any{"jti": "del-me", "exp": futureExp()})
	if _, err := s.Add(ctx, raw); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if err := s.Delete(ctx, "del-me"); err != nil {
		t.Fatalf("Delete existing: %v", err)
	}
	if tokens := s.All(ctx); len(tokens) != 0 {
		t.Errorf("expected empty after Delete, got %v", tokens)
	}
}

func TestInMemoryTokenStore_Delete_NotFound(t *testing.T) {
	s := NewInMemoryTokenStore()
	err := s.Delete(context.Background(), "does-not-exist")
	if err == nil {
		t.Error("Delete of non-existent token should return an error")
	}
}

// ---- EscalationManager edge cases -------------------------------------------

func TestCollectTokens_ExpiredPendingIsRemoved(t *testing.T) {
	pending := NewInMemoryPendingStore()
	ctx := context.Background()
	// Pre-populate an already-expired pending entry.
	pending.Store(ctx, "srv/tool", pendingEscalation{
		JTI:       "jti-expired-pending",
		ExpiresAt: time.Now().Add(-time.Second),
	})

	guard := &mockGuardClient{
		claimTokenFunc: func(_ context.Context, _ string) (string, error) {
			t.Error("ClaimToken must not be called for expired pending")
			return "", nil
		},
	}
	mgr := NewEscalationManager(guard, pending, &mockTokenStore{}, EscalationConfig{},
		NewSingleTenantProvider(nil, ""), nil, "")

	tokens := mgr.CollectTokens(ctx, "srv", "tool")
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens for expired pending, got %d", len(tokens))
	}
	// Expired entry should be cleaned up.
	if _, ok := pending.Get(ctx, "srv/tool"); ok {
		t.Error("expired pending entry should be removed from store")
	}
}

func TestCollectTokens_StoreAddFailureReturnsExisting(t *testing.T) {
	// When escalations.Add fails, CollectTokens must return the pre-existing
	// tokens rather than panicking or returning nil.
	pending := NewInMemoryPendingStore()
	ctx := context.Background()
	pending.Store(ctx, "srv/tool", pendingEscalation{
		JTI:       "jti-add-fail",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	guard := &mockGuardClient{
		claimTokenFunc: func(_ context.Context, _ string) (string, error) {
			return makeTestJWT(map[string]any{"jti": "jti-add-fail", "exp": futureExp()}), nil
		},
	}

	existingTok := shared.EscalationToken{TokenID: "existing"}
	tokens := &mockTokenStore{
		tokens: []shared.EscalationToken{existingTok},
		addFunc: func(_ context.Context, _ string) (shared.EscalationToken, error) {
			return shared.EscalationToken{}, fmt.Errorf("store full")
		},
	}
	mgr := NewEscalationManager(guard, pending, tokens, EscalationConfig{},
		NewSingleTenantProvider(nil, ""), nil, "")

	result := mgr.CollectTokens(ctx, "srv", "tool")
	if len(result) != 1 || result[0].TokenID != "existing" {
		t.Errorf("expected pre-existing tokens on Add failure, got %v", result)
	}
}

func TestStorePending_EmptyJTIIsNoop(t *testing.T) {
	called := false
	guard := &mockGuardClient{
		registerPendingFunc: func(_ context.Context, _, _ string) error {
			called = true
			return nil
		},
	}
	mgr := NewEscalationManager(guard, NewInMemoryPendingStore(), &mockTokenStore{},
		EscalationConfig{}, NewSingleTenantProvider(nil, ""), nil, "")

	err := mgr.StorePending(context.Background(), "srv", "tool", &shared.EscalationPendingError{
		Reason:        "needs approval",
		EscalationJTI: "", // empty → must be no-op
	})
	if err != nil {
		t.Errorf("expected nil error for empty JTI, got %v", err)
	}
	if called {
		t.Error("RegisterPending must not be called when JTI is empty")
	}
}

func TestStorePending_NilGuardIsNoop(t *testing.T) {
	pending := NewInMemoryPendingStore()
	// guard=nil means Guard is not configured.
	mgr := NewEscalationManager(nil, pending, &mockTokenStore{}, EscalationConfig{},
		NewSingleTenantProvider(nil, ""), nil, "")

	err := mgr.StorePending(context.Background(), "srv", "tool", &shared.EscalationPendingError{
		EscalationJTI: "jti-nil-guard",
	})
	if err != nil {
		t.Errorf("expected nil error when guard is nil, got %v", err)
	}
	// Nothing should be stored either.
	if _, ok := pending.Get(context.Background(), "srv/tool"); ok {
		t.Error("pending store must remain empty when guard is nil")
	}
}
