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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

const identityRefreshTTL = 60 * time.Second

// IdentityInfo is the public view of the current identity, safe to return via the management API.
type IdentityInfo struct {
	UserID      string     `json:"user_id"`
	DisplayName string     `json:"display_name,omitempty"`
	SourceType  string     `json:"source_type"`
	TokenExpiry *time.Time `json:"token_expiry,omitempty"` // nil if not OIDC or exp claim absent
}

// IdentityCache resolves and caches the user identity with a short TTL so that
// OIDC token refreshes by enterprise SSO tooling are picked up automatically
// without restarting the gate.
type IdentityCache struct {
	mu          sync.Mutex
	cfg         IdentityConfig
	identity    shared.UserIdentity
	tokenExpiry time.Time // from JWT exp claim; zero if unavailable
	refreshAt   time.Time // when the cache entry should be re-read
}

// NewIdentityCache creates an IdentityCache and performs the initial identity
// resolution. Returns an error if the initial resolution fails.
func NewIdentityCache(ctx context.Context, cfg IdentityConfig) (*IdentityCache, error) {
	c := &IdentityCache{cfg: cfg}
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// Get returns the current identity, refreshing from source if the TTL has elapsed.
// On refresh failure it returns the previously cached identity and logs a warning.
func (c *IdentityCache) Get(ctx context.Context) shared.UserIdentity {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().Before(c.refreshAt) {
		return c.identity
	}
	if err := c.refresh(ctx); err != nil {
		slog.Warn("identity refresh failed, using last known identity", "error", err)
		c.refreshAt = time.Now().Add(10 * time.Second) // back off to avoid log spam
	}
	return c.identity
}

// Info returns public metadata about the current cached identity.
func (c *IdentityCache) Info() IdentityInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	info := IdentityInfo{
		UserID:      c.identity.UserID,
		DisplayName: c.identity.DisplayName,
		SourceType:  c.identity.SourceType,
	}
	if !c.tokenExpiry.IsZero() {
		t := c.tokenExpiry
		info.TokenExpiry = &t
	}
	return info
}

// UpdateToken validates a raw OIDC JWT, writes it to the configured token file,
// and immediately updates the cache. Returns the new identity on success.
// Returns an error if the identity source is not "oidc", the token is invalid,
// or the file cannot be written.
func (c *IdentityCache) UpdateToken(rawJWT string) (shared.UserIdentity, error) {
	if c.cfg.Source != "oidc" {
		return shared.UserIdentity{}, fmt.Errorf("identity source is %q, not oidc; token update not applicable", c.cfg.Source)
	}
	rawJWT = strings.TrimSpace(rawJWT)
	id, expiry, err := identityFromJWT(rawJWT)
	if err != nil {
		return shared.UserIdentity{}, fmt.Errorf("invalid token: %w", err)
	}
	tokenFile, err := expandHome(c.cfg.OIDC.TokenFile)
	if err != nil {
		return shared.UserIdentity{}, fmt.Errorf("expand token file path: %w", err)
	}
	if err := os.WriteFile(tokenFile, []byte(rawJWT+"\n"), 0600); err != nil {
		return shared.UserIdentity{}, fmt.Errorf("write token file: %w", err)
	}
	c.mu.Lock()
	c.identity = id
	c.tokenExpiry = expiry
	c.refreshAt = time.Now().Add(identityRefreshTTL)
	c.mu.Unlock()
	slog.Info("OIDC token updated via management API", "user_id", id.UserID)
	return id, nil
}

// refresh re-resolves the identity from the configured source.
// Must be called with c.mu held.
func (c *IdentityCache) refresh(ctx context.Context) error {
	id, expiry, err := resolveIdentityWithExpiry(ctx, c.cfg)
	if err != nil {
		return err
	}
	c.identity = id
	c.tokenExpiry = expiry
	c.refreshAt = time.Now().Add(identityRefreshTTL)
	return nil
}

// resolveIdentityWithExpiry resolves the identity and returns the JWT expiry
// time (zero if not OIDC or exp claim absent).
//
// When source is "oidc", the token file must exist and contain a valid JWT.
// If it does not, an error is returned — there is no fallback to OS identity.
// This ensures that an enterprise deployment that requires OIDC credentials
// cannot silently degrade to a weaker identity source.
func resolveIdentityWithExpiry(ctx context.Context, cfg IdentityConfig) (shared.UserIdentity, time.Time, error) {
	if cfg.Source == "oidc" {
		tokenFile, err := expandHome(cfg.OIDC.TokenFile)
		if err != nil {
			return shared.UserIdentity{}, time.Time{}, fmt.Errorf("expand oidc token file path: %w", err)
		}
		raw, err := os.ReadFile(tokenFile)
		if err != nil {
			return shared.UserIdentity{}, time.Time{}, fmt.Errorf("read oidc token file %q: %w", tokenFile, err)
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return shared.UserIdentity{}, time.Time{}, fmt.Errorf("oidc token file %q is empty", tokenFile)
		}
		id, expiry, err := identityFromJWT(token)
		if err != nil {
			return shared.UserIdentity{}, time.Time{}, fmt.Errorf("parse oidc token from %q: %w", tokenFile, err)
		}
		return id, expiry, nil
	}
	id, err := resolveOSIdentity(cfg)
	return id, time.Time{}, err
}

// resolveIdentity is kept for compatibility; prefer NewIdentityCache for new code.
func resolveIdentity(ctx context.Context, cfg IdentityConfig) (shared.UserIdentity, error) {
	id, _, err := resolveIdentityWithExpiry(ctx, cfg)
	return id, err
}

// identityFromJWT parses a raw OIDC JWT string, extracts identity claims, and
// returns the token expiry time. It does NOT verify the signature — that is the
// PDP's responsibility.
//
// Warns if the token is already expired or expiring within 5 minutes, but
// still returns the identity so the PDP can make the authoritative decision.
func identityFromJWT(token string) (shared.UserIdentity, time.Time, error) {
	claims, err := unsafeParseJWTClaims(token)
	if err != nil {
		return shared.UserIdentity{}, time.Time{}, fmt.Errorf("parse jwt claims: %w", err)
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
		return shared.UserIdentity{}, time.Time{}, fmt.Errorf("oidc token missing subject claim")
	}

	// Check expiry claim and warn; the PDP is the authority on token validity.
	var expiry time.Time
	if exp, ok := claims["exp"].(float64); ok {
		expiry = time.Unix(int64(exp), 0)
		remaining := time.Until(expiry)
		switch {
		case remaining < 0:
			slog.Warn("OIDC token is expired; requests will likely be denied by the PDP",
				"user_id", id.UserID, "expired_at", expiry.UTC().Format(time.RFC3339))
		case remaining < 5*time.Minute:
			slog.Warn("OIDC token expires soon",
				"user_id", id.UserID, "expires_in", remaining.Round(time.Second).String())
		}
	}

	return id, expiry, nil
}

// resolveOIDCIdentity reads the OIDC token from the configured file.
// Kept for use by tests; production code should use identityFromJWT or IdentityCache.
func resolveOIDCIdentity(_ context.Context, cfg OIDCConfig) (shared.UserIdentity, error) {
	raw, err := os.ReadFile(cfg.TokenFile)
	if err != nil {
		return shared.UserIdentity{}, fmt.Errorf("read oidc token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return shared.UserIdentity{}, fmt.Errorf("oidc token file is empty")
	}
	id, _, err := identityFromJWT(token)
	return id, err
}

// resolveOSIdentity builds a UserIdentity from the OS user. Provided for
// testing/evaluation only; portcullis-keep may be configured to reject it.
func resolveOSIdentity(cfg IdentityConfig) (shared.UserIdentity, error) {
	if cfg.UserID != "" {
		return shared.UserIdentity{
			UserID:      cfg.UserID,
			DisplayName: cfg.DisplayName,
			Groups:      cfg.Groups,
			SourceType:  "os",
		}, nil
	}
	u, err := user.Current()
	if err != nil {
		return shared.UserIdentity{}, fmt.Errorf("resolve os user: %w", err)
	}
	hostname, _ := os.Hostname()
	userID := u.Username
	if hostname != "" {
		userID = u.Username + "@" + hostname
	}
	displayName := u.Name
	if cfg.DisplayName != "" {
		displayName = cfg.DisplayName
	}
	return shared.UserIdentity{
		UserID:      userID,
		DisplayName: displayName,
		Groups:      cfg.Groups,
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
