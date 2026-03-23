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
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
		if cfg.OIDCVerify.JWKSURL == "" {
			return nil, fmt.Errorf("normalizer oidc-verify requires identity.oidc_verify.jwks_url to be set")
		}
		return &oidcVerifyingNormalizer{
			issuer:             cfg.OIDCVerify.Issuer,
			jwksURL:            cfg.OIDCVerify.JWKSURL,
			audiences:          cfg.OIDCVerify.Audiences,
			allowMissingExpiry: cfg.OIDCVerify.AllowMissingExpiry,
			strict:             &strictNormalizer{},
		}, nil
	})
}

// strictNormalizer passes OIDC-sourced identity through unchanged and strips
// all directory claims from OS-sourced identity, retaining only user_id and
// source_type. This prevents Gate from injections unverified group claims.
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
type oidcVerifyingNormalizer struct {
	issuer             string
	jwksURL            string
	audiences          []string
	allowMissingExpiry bool
	strict             *strictNormalizer

	jwksMu sync.RWMutex
	jwks   *jwks
	last   time.Time
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
}

func (n *oidcVerifyingNormalizer) Normalize(ctx context.Context, id shared.UserIdentity) (shared.Principal, error) {
	if id.SourceType != "oidc" {
		return n.strict.Normalize(ctx, id)
	}

	if id.RawToken == "" {
		return shared.Principal{}, fmt.Errorf("oidc identity missing raw token")
	}

	// 1. Verify signature and parse claims
	token, err := jwt.Parse(id.RawToken, n.keyFunc)
	if err != nil {
		return shared.Principal{}, fmt.Errorf("verify oidc token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return shared.Principal{}, fmt.Errorf("invalid oidc token claims")
	}

	// 2. Validate Issuer
	iss, _ := claims.GetIssuer()
	if n.issuer != "" && iss != n.issuer {
		return shared.Principal{}, fmt.Errorf("oidc token issuer %q does not match configured issuer %q", iss, n.issuer)
	}

	// 3. Extract Subject (UserID)
	sub, err := claims.GetSubject()
	if err != nil {
		return shared.Principal{}, fmt.Errorf("parse oidc token subject: %w", err)
	}
	if sub == "" {
		return shared.Principal{}, fmt.Errorf("oidc token missing sub claim")
	}

	// 4. Validate Audiences
	if len(n.audiences) > 0 {
		aud, _ := claims.GetAudience()
		found := false
		for _, a := range n.audiences {
			for _, t := range aud {
				if a == t {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return shared.Principal{}, fmt.Errorf("oidc token audience mismatch (aud=%v, expected=%v)", aud, n.audiences)
		}
	}

	// 5. Validate Expiry
	exp, err := claims.GetExpirationTime()
	if err != nil {
		return shared.Principal{}, fmt.Errorf("parse oidc token expiry: %w", err)
	}
	if exp == nil {
		if !n.allowMissingExpiry {
			return shared.Principal{}, fmt.Errorf("oidc token missing exp claim (required by default)")
		}
	} else if time.Now().After(exp.Time) {
		return shared.Principal{}, fmt.Errorf("oidc token is expired (exp=%v)", exp.Time)
	}

	// Use claims from the verified token
	email, _ := claims["email"].(string)
	displayName, _ := claims["name"].(string)
	
	var groups []string
	if g, ok := claims["groups"].([]any); ok {
		for _, v := range g {
			if s, ok := v.(string); ok {
				groups = append(groups, s)
			}
		}
	}

	var roles []string
	if r, ok := claims["roles"].([]any); ok {
		for _, v := range r {
			if s, ok := v.(string); ok {
				roles = append(roles, s)
			}
		}
	}

	dept, _ := claims["department"].(string)
	
	var amr []string
	if a, ok := claims["amr"].([]any); ok {
		for _, v := range a {
			if s, ok := v.(string); ok {
				amr = append(amr, s)
			}
		}
	}

	var expUnix int64
	if exp != nil {
		expUnix = exp.Unix()
	}

	return shared.Principal{
		UserID:      sub, // Use verified subject from token
		Email:       email,
		DisplayName: displayName,
		Groups:      groups,
		Roles:       roles,
		Department:  dept,
		AuthMethod:  amr,
		TokenExpiry: expUnix,
		SourceType:  id.SourceType,
	}, nil
}

func (n *oidcVerifyingNormalizer) keyFunc(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("missing kid in token header")
	}

	// 1. Try with cached JWKS
	keys, err := n.getJWKS(false)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}

	for _, k := range keys.Keys {
		if k.Kid == kid {
			return n.buildRSAPublicKey(k)
		}
	}

	// 2. Kid miss: force immediate refresh and retry
	slog.Info("JWKS kid miss; forcing immediate refresh", "kid", kid)
	keys, err = n.getJWKS(true)
	if err != nil {
		return nil, fmt.Errorf("refresh JWKS: %w", err)
	}

	for _, k := range keys.Keys {
		if k.Kid == kid {
			return n.buildRSAPublicKey(k)
		}
	}

	return nil, fmt.Errorf("kid %q not found in JWKS after refresh", kid)
}

func (n *oidcVerifyingNormalizer) buildRSAPublicKey(k jwk) (*rsa.PublicKey, error) {
	// Construct RSA Public Key from JWK
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode JWK n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode JWK e: %w", err)
	}

	var e int
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}

func (n *oidcVerifyingNormalizer) getJWKS(force bool) (*jwks, error) {
	if !force {
		n.jwksMu.RLock()
		if n.jwks != nil && time.Since(n.last) < 1*time.Hour {
			defer n.jwksMu.RUnlock()
			return n.jwks, nil
		}
		n.jwksMu.RUnlock()
	}

	n.jwksMu.Lock()
	defer n.jwksMu.Unlock()

	// Re-check after acquiring lock (unless forced)
	if !force && n.jwks != nil && time.Since(n.last) < 1*time.Hour {
		return n.jwks, nil
	}

	resp, err := http.Get(n.jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var keys jwks
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}

	n.jwks = &keys
	n.last = time.Now()
	return n.jwks, nil
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
