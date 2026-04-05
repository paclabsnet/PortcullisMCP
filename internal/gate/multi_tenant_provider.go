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
	"bytes"
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// MultiTenantProvider implements TenancyProvider for multi-tenant deployments.
// It enforces per-request credential fingerprinting, disables all single-tenant
// capabilities, and converts escalation/deny errors into opaque SIEM log entries.
type MultiTenantProvider struct {
	tokenHeader string
	sessions    SessionStore
	logChan     chan<- DecisionLogEntry
}

// NewMultiTenantProvider creates a MultiTenantProvider. logChan may be nil at
// construction time and set later (e.g. once the Gate's channel is allocated).
func NewMultiTenantProvider(tokenHeader string, sessions SessionStore, logChan chan<- DecisionLogEntry) *MultiTenantProvider {
	return &MultiTenantProvider{
		tokenHeader: tokenHeader,
		sessions:    sessions,
		logChan:     logChan,
	}
}

// Authenticate extracts the token from the configured header, validates any
// existing session fingerprint, and allocates a new session ID when needed.
func (p *MultiTenantProvider) Authenticate(r *http.Request) (string, string, error) {
	rawToken := ""
	if p.tokenHeader != "" {
		rawToken = r.Header.Get(p.tokenHeader)
	}
	if rawToken == "" {
		// Middleware will return 401; return empty values without error.
		return "", "", nil
	}

	sessionID := r.Header.Get("Mcp-Session-Id")
	ctx := r.Context()

	if p.sessions != nil {
		if sessionID != "" {
			storedState, _, err := p.sessions.GetSession(ctx, sessionID)
			switch {
			case errors.Is(err, ErrSessionNotFound):
				sessionID = "" // treat as no session; allocate a new one below
			case err != nil:
				return "", "", err
			default:
				if !bytes.Equal(storedState, credentialFingerprint(rawToken)) {
					return "", "", errors.New("forbidden: session fingerprint mismatch")
				}
			}
		}

		if sessionID == "" {
			sessionID = uuid.NewString()
			fp := credentialFingerprint(rawToken)
			if err := p.sessions.SaveSession(ctx, sessionID, "", fp); err != nil {
				return "", "", err
			}
		}
	}

	return rawToken, sessionID, nil
}

// Capabilities returns the restricted feature set for multi-tenant mode.
func (p *MultiTenantProvider) Capabilities() Capabilities {
	return Capabilities{
		AllowLocalFS:      false,
		AllowManagementUI: false,
		AllowGuardPeer:    false,
		AllowHumanInLoop:  false,
		AllowNativeTools:  false,
	}
}

// MapPolicyError intercepts escalation and deny errors in multi-tenant mode,
// emits a SIEM DecisionLogEntry, and returns an opaque deny marker to the
// caller. Infrastructure errors (transport failures, unknown errors) are not
// intercepted and return (nil, false) so they propagate normally.
func (p *MultiTenantProvider) MapPolicyError(ctx context.Context, err error, tool, traceID string, cfg *Config) (*mcp.CallToolResult, bool) {
	var escalationErr *shared.EscalationPendingError
	var denyErr *shared.DenyError

	if !errors.As(err, &escalationErr) && !errors.As(err, &denyErr) && !errors.Is(err, shared.ErrDenied) {
		return nil, false
	}

	sid, _ := SessionIDFromContext(ctx)
	if p.logChan != nil {
		select {
		case p.logChan <- DecisionLogEntry{
			Timestamp: time.Now().UTC(),
			SessionID: sid,
			TraceID:   traceID,
			ToolName:  tool,
			Decision:  "deny",
			Reason:    "multi-tenant: escalation intercepted",
			Source:    "gate-multitenant",
		}:
		default:
		}
	}

	marker := cfg.Responsibility.Escalation.NoEscalationMarker
	if marker == "" {
		marker = "Access denied."
	}
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: marker}},
	}, true
}
