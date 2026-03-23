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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// IdentityNormalizer transforms a raw UserIdentity received from Gate into a
// normalized Principal suitable for forwarding to the PDP.
//
// A non-nil error means the normalizer could not process the identity (e.g.,
// invalid token, misconfigured normalizer). Keep returns 503 in that case.
type IdentityNormalizer interface {
	Normalize(ctx context.Context, id shared.UserIdentity) (shared.Principal, error)
}

// NormalizerFactory is a function that creates an IdentityNormalizer from the
// provided configuration.
type NormalizerFactory func(cfg IdentityConfig) (IdentityNormalizer, error)

var (
	normalizersMu sync.RWMutex
	normalizers   = make(map[string]NormalizerFactory)
)

// RegisterNormalizer adds a new identity normalizer implementation to the global
// registry. It should be called from an init() function.
func RegisterNormalizer(name string, factory NormalizerFactory) {
	normalizersMu.Lock()
	defer normalizersMu.Unlock()
	normalizers[name] = factory
}

func init() {
	RegisterNormalizer("strict", func(cfg IdentityConfig) (IdentityNormalizer, error) {
		return &strictNormalizer{}, nil
	})
	RegisterNormalizer("passthrough", func(cfg IdentityConfig) (IdentityNormalizer, error) {
		return &passthroughNormalizer{silenced: cfg.AcceptForgedIdentities}, nil
	})
	RegisterNormalizer("oidc-verify", func(cfg IdentityConfig) (IdentityNormalizer, error) {
		if cfg.OIDCVerify.Issuer == "" {
			return nil, fmt.Errorf("normalizer oidc-verify requires identity.oidc_verify.issuer to be set")
		}
		return &oidcVerifyingNormalizer{
			issuer: cfg.OIDCVerify.Issuer,
			strict: &strictNormalizer{},
		}, nil
	})
}

// strictNormalizer passes OIDC-sourced identity through unchanged and strips
// all directory claims from OS-sourced identity, retaining only user_id and
// source_type. This prevents Gate from injecting unverified group claims.
type strictNormalizer struct{}

func (n *strictNormalizer) Normalize(_ context.Context, id shared.UserIdentity) (shared.Principal, error) {
	if id.SourceType != "os" {
		return shared.Principal{
			UserID:      id.UserID,
			Email:       id.Email,
			DisplayName: id.DisplayName,
			Groups:      id.Groups,
			Roles:       id.Roles,
			Department:  id.Department,
			AuthMethod:  id.AuthMethod,
			TokenExpiry: id.TokenExpiry,
			SourceType:  id.SourceType,
		}, nil
	}
	slog.Warn("keep: os-sourced identity received — directory claims stripped; configure normalizer: passthrough for local evaluation",
		"user_id", id.UserID,
	)
	return shared.Principal{
		UserID:     id.UserID,
		SourceType: id.SourceType,
	}, nil
}

// passthroughNormalizer accepts all identity fields as-is. Intended for local
// evaluation and sandbox deployments only. Logs a warning on every request
// unless silenced is true.
type passthroughNormalizer struct {
	silenced bool
}

func (n *passthroughNormalizer) Normalize(_ context.Context, id shared.UserIdentity) (shared.Principal, error) {
	if !n.silenced {
		slog.Warn("keep: identity passthrough — claims are unverified and MUST NOT be used in production; "+
			"set identity.accept_forged_identities=true to suppress this warning",
			"user_id", id.UserID,
			"source", id.SourceType,
		)
	}
	return shared.Principal{
		UserID:      id.UserID,
		Email:       id.Email,
		DisplayName: id.DisplayName,
		Groups:      id.Groups,
		Roles:       id.Roles,
		Department:  id.Department,
		AuthMethod:  id.AuthMethod,
		TokenExpiry: id.TokenExpiry,
		SourceType:  id.SourceType,
	}, nil
}

// oidcVerifyingNormalizer validates OIDC token claims before forwarding to
// the PDP. It rejects expired tokens and, when an issuer is configured,
// tokens not issued by that issuer. OS-sourced identities are handled by
// the embedded strictNormalizer.
//
// Note: JWT signature verification against JWKS is not yet implemented.
// The PDP is the authority on cryptographic token validity.
type oidcVerifyingNormalizer struct {
	issuer string
	strict *strictNormalizer
}

func (n *oidcVerifyingNormalizer) Normalize(ctx context.Context, id shared.UserIdentity) (shared.Principal, error) {
	if id.SourceType != "oidc" {
		return n.strict.Normalize(ctx, id)
	}

	if id.RawToken == "" {
		return shared.Principal{}, fmt.Errorf("oidc identity missing raw token")
	}

	if id.TokenExpiry != 0 && time.Now().Unix() > id.TokenExpiry {
		return shared.Principal{}, fmt.Errorf("oidc token is expired (exp=%d)", id.TokenExpiry)
	}

	if n.issuer != "" && id.RawToken != "" {
		iss, err := jwtIssuer(id.RawToken)
		if err != nil {
			return shared.Principal{}, fmt.Errorf("parse oidc token issuer: %w", err)
		}
		if iss != n.issuer {
			return shared.Principal{}, fmt.Errorf("oidc token issuer %q does not match configured issuer %q", iss, n.issuer)
		}
	}

	return shared.Principal{
		UserID:      id.UserID,
		Email:       id.Email,
		DisplayName: id.DisplayName,
		Groups:      id.Groups,
		Roles:       id.Roles,
		Department:  id.Department,
		AuthMethod:  id.AuthMethod,
		TokenExpiry: id.TokenExpiry,
		SourceType:  id.SourceType,
	}, nil
}

// jwtIssuer extracts the iss claim from a JWT without verifying the signature.
func jwtIssuer(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("not a JWT: expected 3 parts, got %d", len(parts))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode jwt payload: %w", err)
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return "", fmt.Errorf("unmarshal jwt claims: %w", err)
	}
	return claims.Issuer, nil
}

// buildIdentityNormalizer constructs the configured IdentityNormalizer using
// the global registry.
func buildIdentityNormalizer(cfg IdentityConfig) (IdentityNormalizer, error) {
	name := cfg.Normalizer
	if name == "" {
		name = "strict"
	}

	normalizersMu.RLock()
	factory, ok := normalizers[name]
	normalizersMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown identity normalizer %q; supported: strict, passthrough, oidc-verify", name)
	}

	return factory(cfg)
}
