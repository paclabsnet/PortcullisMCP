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
	"log/slog"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

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
	// In proactive mode it also pushes the request to Guard. Returns a
	// user-facing error only if the proactive push fails.
	StorePending(ctx context.Context, serverName, toolName string, err error) error

	// StartPolling starts the background Guard poll worker. It is a no-op if
	// Guard is not configured.
	StartPolling(ctx context.Context)
}

// DefaultEscalationManager implements EscalationManager using a live GuardSource.
type DefaultEscalationManager struct {
	guard       GuardSource
	pending     PendingEscalationStore
	escalations EscalationTokenStore
	cfg         EscalationConfig
	provider    TenancyProvider
	identity    IdentitySource
}

// NewEscalationManager creates a DefaultEscalationManager. guard may be nil if
// Guard is not configured; CollectTokens and StorePending still work but skip
// all Guard interactions.
func NewEscalationManager(
	guard GuardSource,
	pending PendingEscalationStore,
	escalations EscalationTokenStore,
	cfg EscalationConfig,
	provider TenancyProvider,
	identity IdentitySource,
) *DefaultEscalationManager {
	return &DefaultEscalationManager{
		guard:       guard,
		pending:     pending,
		escalations: escalations,
		cfg:         cfg,
		provider:    provider,
		identity:    identity,
	}
}

// CollectTokens returns escalation tokens, opportunistically claiming a
// Guard-approved token for the given server/tool before returning.
func (m *DefaultEscalationManager) CollectTokens(ctx context.Context, serverName, toolName string) []shared.EscalationToken {
	tokens := m.escalations.All()

	if m.guard == nil {
		return tokens
	}

	key := serverName + "/" + toolName
	pending, hasPending := m.pending.Get(key)

	if !hasPending {
		return tokens
	}
	if pending.ExpiresAt.Before(time.Now()) {
		m.pending.Delete(key)
		return tokens
	}

	claimCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	raw, err := m.guard.ClaimToken(claimCtx, pending.JTI)
	if err != nil {
		slog.Warn("guard claim token failed", "jti", pending.JTI, "error", err)
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

	m.pending.Delete(key)
	return m.escalations.All()
}

// StorePending records a pending escalation. It is a no-op if the provider
// disallows human-in-the-loop, if err is not an EscalationPendingError, if
// the JTI is empty, or if Guard is not configured.
func (m *DefaultEscalationManager) StorePending(ctx context.Context, serverName, toolName string, err error) error {
	if m.provider != nil && !m.provider.Capabilities().AllowHumanInLoop {
		return nil
	}

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

	if m.cfg.Strategy == "proactive" {
		pushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if regErr := m.guard.RegisterPending(pushCtx, escalationErr.EscalationJTI, escalationErr.PendingJWT); regErr != nil {
			slog.Error("proactive: failed to register pending escalation with Guard",
				"jti", escalationErr.EscalationJTI, "error", regErr)
			return fmt.Errorf("escalation required but Guard is currently unreachable")
		}
		slog.Info("proactive: registered pending escalation with Guard",
			"jti", escalationErr.EscalationJTI, "server", serverName, "tool", toolName)
	}

	key := serverName + "/" + toolName
	expiry := time.Now().Add(24 * time.Hour)

	m.pending.Store(key, pendingEscalation{
		ServerName: serverName,
		ToolName:   toolName,
		JTI:        escalationErr.EscalationJTI,
		ExpiresAt:  expiry,
	})

	slog.Info("stored pending escalation",
		"server", serverName, "tool", toolName, "jti", escalationErr.EscalationJTI)
	return nil
}

// StartPolling starts the background Guard poll worker. It is a no-op if Guard
// is not configured.
func (m *DefaultEscalationManager) StartPolling(ctx context.Context) {
	if m.guard == nil {
		return
	}
	interval := 60 * time.Second
	if m.cfg.PollInterval > 0 {
		interval = time.Duration(m.cfg.PollInterval) * time.Second
	}
	slog.Info("guard poll worker starting", "interval", interval)
	go func() {
		m.claimAllUnclaimedTokens(ctx)
		m.pollGuardWorker(ctx)
	}()
}

func (m *DefaultEscalationManager) pollGuardWorker(ctx context.Context) {
	interval := 60 * time.Second
	if m.cfg.PollInterval > 0 {
		interval = time.Duration(m.cfg.PollInterval) * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.claimAllUnclaimedTokens(ctx)
		}
	}
}

func (m *DefaultEscalationManager) claimAllUnclaimedTokens(ctx context.Context) {
	if m.identity == nil {
		return
	}
	userID := m.identity.Get(ctx).UserID
	if userID == "" {
		return
	}

	listCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	unclaimed, err := m.guard.ListUnclaimedTokens(listCtx, userID)
	if err != nil {
		slog.Warn("poll guard unclaimed tokens failed", "error", err)
		return
	}
	slog.Info("polled guard for unclaimed tokens", "user_id", userID, "count", len(unclaimed))
	if len(unclaimed) == 0 {
		return
	}

	for _, entry := range unclaimed {
		claimCtx, claimCancel := context.WithTimeout(ctx, 5*time.Second)
		raw, claimErr := m.guard.ClaimToken(claimCtx, entry.JTI)
		claimCancel()

		if claimErr != nil {
			slog.Warn("guard poll claim failed", "jti", entry.JTI, "error", claimErr)
			continue
		}
		if raw == "" {
			continue
		}

		tok, storeErr := m.escalations.Add(ctx, raw)
		if storeErr != nil {
			slog.Warn("store polled token failed", "jti", entry.JTI, "error", storeErr)
			continue
		}

		slog.Info("claimed escalation token via poll", "jti", entry.JTI, "token_id", tok.TokenID)

		m.pending.DeleteByJTI(entry.JTI)
	}
}
