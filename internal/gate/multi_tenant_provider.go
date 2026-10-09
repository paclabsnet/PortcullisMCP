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
	"errors"
	"net/http"

	"github.com/google/uuid"
)

// MultiTenantProvider implements TenancyProvider for multi-tenant deployments.
// It enforces per-request credential fingerprinting, disables all single-tenant
// capabilities, and converts escalation/deny errors into opaque SIEM log entries.
type MultiTenantProvider struct {
	tokenHeader string
	sessions    SessionStore
	logger      DecisionLogger
}

// NewMultiTenantProvider creates a MultiTenantProvider. logger may be nil at
// construction time and set later (e.g. once the Gate's logger is allocated).
func NewMultiTenantProvider(tokenHeader string, sessions SessionStore, logger DecisionLogger) *MultiTenantProvider {
	return &MultiTenantProvider{
		tokenHeader: tokenHeader,
		sessions:    sessions,
		logger:      logger,
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
		fp := credentialFingerprint(rawToken)
		if sessionID != "" {
			storedState, _, err := p.sessions.GetSession(ctx, sessionID)
			switch {
			case errors.Is(err, ErrSessionNotFound):
				// The SDK assigns Mcp-Session-Id itself (returned to the client on
				// initialize) and we never see it before the first follow-up request.
				// Bind the client-supplied ID to this credential fingerprint
				// (trust on first use) so the ID stays stable across requests and
				// later mismatches are rejected. Do NOT mint a replacement ID: the
				// client would never learn it.
				// SaveSessionIfAbsent makes the bind atomic: if a concurrent request
				// bound the ID first, validate against its fingerprint instead of
				// overwriting it.
				stored, err := p.sessions.SaveSessionIfAbsent(ctx, sessionID, "", fp)
				if err != nil {
					return "", "", err
				}
				if !stored {
					existing, _, err := p.sessions.GetSession(ctx, sessionID)
					if err != nil {
						return "", "", err
					}
					if !bytes.Equal(existing, fp) {
						return "", "", errors.New("forbidden: session fingerprint mismatch")
					}
				}
			case err != nil:
				return "", "", err
			default:
				if !bytes.Equal(storedState, fp) {
					return "", "", errors.New("forbidden: session fingerprint mismatch")
				}
			}
		} else {
			// No client session yet (e.g. initialize): allocate an internal ID.
			sessionID = uuid.NewString()
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
		AllowNativeTools:  false,
	}
}
