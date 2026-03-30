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
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// escalationRequestClaims are the JWT claims Keep embeds in escalation request tokens.
// Guard and enterprise workflow plugins decode these to render approval pages.
type escalationRequestClaims struct {
	jwt.RegisteredClaims
	UserID          string         `json:"uid"`
	UserDisplayName string         `json:"uname,omitempty"`
	Server          string         `json:"srv"`
	Tool            string         `json:"tool"`
	Reason          string         `json:"reason"`
	EscalationScope []map[string]any `json:"scope,omitempty"`
}

// EscalationSigner creates Keep-signed escalation request JWTs.
// Workflow plugins embed these JWTs in approval URLs or workflow tickets.
// If no signing key is configured, Sign returns an empty string (no JWT).
type EscalationSigner struct {
	mu  sync.Mutex
	key []byte
	ttl time.Duration
}

// NewEscalationSigner creates an EscalationSigner from the keep signing config.
// Returns nil if no key is configured — callers must handle a nil signer gracefully.
func NewEscalationSigner(cfg SigningConfig) (*EscalationSigner, error) {
	if cfg.Key == "" {
		return nil, nil
	}
	ttl := time.Duration(cfg.TTL) * time.Second
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	return &EscalationSigner{key: []byte(cfg.Key), ttl: ttl}, nil
}

// Sign creates a signed JWT encoding the full escalation request context.
// Returns the signed JWT string, the JWT ID (jti), and any error.
// The JTI is stable and must be copied into the issued escalation token by Guard
// so Gate can correlate the approved token back to the pending escalation.
func (s *EscalationSigner) Sign(req AuthorizedRequest, reason string, scope []map[string]any) (jwtStr string, jti string, err error) {
	if s == nil {
		return "", "", fmt.Errorf("escalation signing not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	jti = uuid.NewString()
	claims := escalationRequestClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    shared.ServiceKeep,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
		},
		UserID:          req.Principal.UserID,
		UserDisplayName: req.Principal.DisplayName,
		Server:          req.ServerName,
		Tool:            req.ToolName,
		Reason:          reason,
		EscalationScope: scope,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, signErr := token.SignedString(s.key)
	return signed, jti, signErr
}
