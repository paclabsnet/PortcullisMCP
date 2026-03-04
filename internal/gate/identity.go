package gate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// resolveIdentity builds a UserIdentity for the current session.
// It tries sources in priority order: OIDC token file, then OS username fallback.
func resolveIdentity(ctx context.Context, cfg IdentityConfig) (shared.UserIdentity, error) {
	if cfg.Source == "oidc" {
		id, err := resolveOIDCIdentity(ctx, cfg.OIDC)
		if err == nil {
			return id, nil
		}
		// Fall through to OS fallback on error.
	}
	return resolveOSIdentity()
}

// resolveOIDCIdentity reads the OIDC token from the configured file and
// extracts identity claims from the JWT payload.
// It does NOT verify the token signature — that is the PDP's responsibility.
func resolveOIDCIdentity(_ context.Context, cfg OIDCConfig) (shared.UserIdentity, error) {
	raw, err := os.ReadFile(cfg.TokenFile)
	if err != nil {
		return shared.UserIdentity{}, fmt.Errorf("read oidc token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return shared.UserIdentity{}, fmt.Errorf("oidc token file is empty")
	}

	claims, err := unsafeParseJWTClaims(token)
	if err != nil {
		return shared.UserIdentity{}, fmt.Errorf("parse oidc token claims: %w", err)
	}

	id := shared.UserIdentity{
		SourceType: "oidc",
		RawToken:   token,
	}

	if v, ok := claims["sub"].(string); ok {
		id.UserID = v
	}
	if v, ok := claims["upn"].(string); ok && id.UserID == "" {
		id.UserID = v
	}
	if v, ok := claims["email"].(string); ok && id.UserID == "" {
		id.UserID = v
	}
	if v, ok := claims["name"].(string); ok {
		id.DisplayName = v
	} else if v, ok := claims["preferred_username"].(string); ok {
		id.DisplayName = v
	}
	if groups, ok := claims["groups"].([]any); ok {
		for _, g := range groups {
			if s, ok := g.(string); ok {
				id.Groups = append(id.Groups, s)
			}
		}
	}

	if id.UserID == "" {
		return shared.UserIdentity{}, fmt.Errorf("oidc token missing subject claim")
	}
	return id, nil
}

// resolveOSIdentity builds a UserIdentity from the OS user. Provided for
// testing/evaluation only; portcullis-keep may be configured to reject it.
func resolveOSIdentity() (shared.UserIdentity, error) {
	u, err := user.Current()
	if err != nil {
		return shared.UserIdentity{}, fmt.Errorf("resolve os user: %w", err)
	}
	hostname, _ := os.Hostname()
	userID := u.Username
	if hostname != "" {
		userID = u.Username + "@" + hostname
	}
	return shared.UserIdentity{
		UserID:      userID,
		DisplayName: u.Name,
		SourceType:  "os",
	}, nil
}

// unsafeParseJWTClaims decodes the payload of a JWT without verifying the
// signature. Used only to extract display claims; the PDP must verify.
func unsafeParseJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT: expected 3 parts, got %d", len(parts))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode jwt payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal jwt claims: %w", err)
	}
	return claims, nil
}
