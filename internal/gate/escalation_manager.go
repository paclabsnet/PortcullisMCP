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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	"github.com/paclabsnet/PortcullisMCP/internal/telemetry"
)

// GuardUnavailableError is returned by StorePending when the Guard service
// cannot be reached. policyErrToResult converts it to an agent-friendly
// "Authorization system unavailable" message.
type GuardUnavailableError struct {
	JTI string
	Err error
}

func (e *GuardUnavailableError) Error() string {
	return fmt.Sprintf("escalation required but Guard is currently unreachable (jti=%s): %v", e.JTI, e.Err)
}

func (e *GuardUnavailableError) Unwrap() error { return e.Err }

// pendingEscalation tracks an in-flight escalation request awaiting Guard approval.
type pendingEscalation struct {
	ServerName string
	ToolName   string
	JTI        string
	ExpiresAt  time.Time
}

// EscalationManager abstracts Guard interactions and pending escalation state.
type EscalationManager interface {
	// CollectTokens returns the caller's current escalation tokens. If a pending
	// escalation for the given server/tool has been approved by Guard, it is
	// claimed and added to the token store before returning.
	CollectTokens(ctx context.Context, serverName, toolName string) []shared.EscalationToken

	// StorePending records a pending escalation from an EscalationPendingError.
	// It also pushes the request to Guard. Returns a user-facing error only if
	// the proactive push fails.
	StorePending(ctx context.Context, serverName, toolName string, err error) error
}

// DefaultEscalationManager implements EscalationManager using a live GuardSource.
type DefaultEscalationManager struct {
	guard       GuardSource
	pending     PendingEscalationStore
	escalations EscalationTokenStore
	provider    TenancyProvider
	identity    IdentitySource
	scope       string // "session" | "fingerprint" | ""
}

// NewEscalationManager creates a DefaultEscalationManager. guard may be nil if
// Guard is not configured; CollectTokens and StorePending still work but skip
// all Guard interactions. scope is the top-level Config.Escalation value and
// controls per-request key partitioning ("session", "fingerprint", or "").
func NewEscalationManager(
	guard GuardSource,
	pending PendingEscalationStore,
	escalations EscalationTokenStore,
	_ EscalationConfig,
	provider TenancyProvider,
	identity IdentitySource,
	scope string,
) *DefaultEscalationManager {
	return &DefaultEscalationManager{
		guard:       guard,
		pending:     pending,
		escalations: escalations,
		provider:    provider,
		identity:    identity,
		scope:       scope,
	}
}

// pendingKey returns the storage key for a pending escalation request,
// partitioned by the caller's session or credential fingerprint when a scope
// is configured.
func (m *DefaultEscalationManager) pendingKey(ctx context.Context, serverName, toolName string) string {
	bare := serverName + "/" + toolName
	prefix := resolveStoragePrefix(ctx, m.scope, m.identity)
	if prefix == "" {
		return bare
	}
	return prefix + ":" + bare
}

// CollectTokens returns escalation tokens, opportunistically claiming a
// Guard-approved token for the given server/tool before returning.
//
// When a pending escalation is found and a Guard claim is attempted, the
// outcome is recorded as a structured "lazy_claim" log entry containing:
//
//	phase, jti, trace_id, scope_type, scope_key_hash, guard_status_code,
//	outcome ("success"|"not_found"|"error"), error_class, elapsed_ms.
//
// scope_key_hash is the first 8 hex characters of the SHA-256 digest of the
// raw storage prefix string (e.g. "sess:abc123" or "fp:xyz"), providing a
// stable, non-reversible token for log correlation without leaking credentials.
// The algorithm is SHA-256 / hex / first 8 chars and MUST NOT change between
// versions to ensure log queries remain valid across upgrades.
func (m *DefaultEscalationManager) CollectTokens(ctx context.Context, serverName, toolName string) []shared.EscalationToken {
	tokens := m.escalations.All(ctx)

	if m.guard == nil {
		return tokens
	}

	key := m.pendingKey(ctx, serverName, toolName)
	pending, hasPending := m.pending.Get(ctx, key)

	if !hasPending {
		return tokens
	}
	if pending.ExpiresAt.Before(time.Now()) {
		m.pending.Delete(ctx, key)
		return tokens
	}

	// Compute scope_key_hash: first 8 hex chars of SHA-256(rawPrefix).
	// Algorithm: SHA-256 / hex encoding / truncated to 8 characters.
	rawPrefix := resolveStoragePrefix(ctx, m.scope, m.identity)
	h := sha256.Sum256([]byte(rawPrefix))
	scopeKeyHash := hex.EncodeToString(h[:])[:8]

	traceID := telemetry.TraceIDFromContext(ctx)

	claimCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	start := time.Now()
	raw, claimErr := m.guard.ClaimToken(claimCtx, pending.JTI)
	elapsedMs := time.Since(start).Milliseconds()

	// Determine guard_status_code, outcome, and error_class for telemetry.
	guardStatusCode := 0
	outcome := "success"
	errorClass := ""

	if claimErr != nil {
		outcome = "error"
		var apiErr *GuardAPIError
		if errors.As(claimErr, &apiErr) {
			guardStatusCode = apiErr.StatusCode
			switch apiErr.StatusCode {
			case 401, 403:
				errorClass = "unauthorized"
			case 503, 502, 504:
				errorClass = "service_unavailable"
			default:
				errorClass = "http_error"
			}
		} else if errors.Is(claimErr, context.DeadlineExceeded) {
			errorClass = "network_timeout"
		} else {
			errorClass = "unknown"
		}
	} else if raw == "" {
		outcome = "not_found"
		guardStatusCode = 404
	} else {
		guardStatusCode = 200
	}

	slog.Info("lazy_claim",
		"phase", "lazy_claim",
		"jti", pending.JTI,
		"trace_id", traceID,
		"scope_type", m.scope,
		"scope_key_hash", scopeKeyHash,
		"guard_status_code", guardStatusCode,
		"outcome", outcome,
		"error_class", errorClass,
		"elapsed_ms", elapsedMs,
	)

	if claimErr != nil {
		slog.Warn("guard claim token failed", "jti", pending.JTI, "error", claimErr)
		return tokens
	}
	if raw == "" {
		return tokens
	}

	tok, err := m.escalations.Add(ctx, raw)
	if err != nil {
		slog.Warn("store claimed escalation token failed", "jti", pending.JTI, "error", err)
		return tokens
	}

	slog.Info("claimed escalation token from guard",
		"jti", pending.JTI, "token_id", tok.TokenID,
		"server", serverName, "tool", toolName)

	m.pending.Delete(ctx, key)
	return m.escalations.All(ctx)
}

// StorePending records a pending escalation. It is a no-op if err is not an
// EscalationPendingError, if the JTI is empty, or if Guard is not configured.
// Callers must only invoke StorePending when escalation is active (Escalation != "disabled").
func (m *DefaultEscalationManager) StorePending(ctx context.Context, serverName, toolName string, err error) error {
	var escalationErr *shared.EscalationPendingError
	if !errors.As(err, &escalationErr) {
		return nil
	}
	if escalationErr.EscalationJTI == "" {
		return nil
	}
	if m.guard == nil {
		return nil
	}

	// Always register proactively with Guard (standardized flow; Strategy field removed).
	pushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if regErr := m.guard.RegisterPending(pushCtx, escalationErr.EscalationJTI, escalationErr.PendingJWT); regErr != nil {
		slog.Error("failed to register pending escalation with Guard",
			"jti", escalationErr.EscalationJTI, "error", regErr)
		return &GuardUnavailableError{JTI: escalationErr.EscalationJTI, Err: regErr}
	}
	slog.Info("registered pending escalation with Guard",
		"jti", escalationErr.EscalationJTI, "server", serverName, "tool", toolName)

	key := m.pendingKey(ctx, serverName, toolName)
	expiry := time.Now().Add(24 * time.Hour)

	m.pending.Store(ctx, key, pendingEscalation{
		ServerName: serverName,
		ToolName:   toolName,
		JTI:        escalationErr.EscalationJTI,
		ExpiresAt:  expiry,
	})

	slog.Info("stored pending escalation",
		"server", serverName, "tool", toolName, "jti", escalationErr.EscalationJTI)
	return nil
}

