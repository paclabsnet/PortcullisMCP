package keep

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
// Returns an error only if JWT signing fails; missing scope is allowed.
func (s *EscalationSigner) Sign(req shared.EnrichedMCPRequest, reason string, scope []map[string]any) (string, error) {
	if s == nil {
		return "", fmt.Errorf("escalation signing not configured")
	}
	now := time.Now()
	claims := escalationRequestClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "portcullis-keep",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
		},
		UserID:          req.UserIdentity.UserID,
		UserDisplayName: req.UserIdentity.DisplayName,
		Server:          req.ServerName,
		Tool:            req.ToolName,
		Reason:          reason,
		EscalationScope: scope,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.key)
}
