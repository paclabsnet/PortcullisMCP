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
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	identity "github.com/paclabsnet/PortcullisMCP/internal/shared/identity"
)

// IdentityNormalizer is an alias for identity.Normalizer.
type IdentityNormalizer = identity.Normalizer

func init() {
	identity.Register("passthrough", func(cfg identity.NormalizerConfig) (identity.Normalizer, error) {
		return &passthroughNormalizer{silenced: cfg.AcceptForgedIdentities}, nil
	})

	identity.Register("oidc-verify", func(cfg identity.NormalizerConfig) (identity.Normalizer, error) {
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
			maxTokenAgeSecs:    cfg.OIDCVerify.MaxTokenAgeSecs,
			httpClient:         &http.Client{Timeout: 10 * time.Second},
		}, nil
	})
}

// passthroughNormalizer accepts all identity fields as-is.
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
		UserID:            id.UserID,
		Email:             id.Email,
		DisplayName:       id.DisplayName,
		Groups:            id.Groups,
		Roles:             id.Roles,
		Department:        id.Department,
		AuthMethod:        id.AuthMethod,
		PreferredUsername: id.PreferredUsername,
		ACR:               id.ACR,
		TokenExpiry:       id.TokenExpiry,
		SourceType:        id.SourceType,
	}, nil
}

// oidcVerifyingNormalizer validates OIDC token claims before forwarding to the PDP.
type oidcVerifyingNormalizer struct {
	issuer             string
	jwksURL            string
	audiences          []string
	allowMissingExpiry bool
	maxTokenAgeSecs    int
	httpClient         *http.Client // used for JWKS fetches; must have Timeout set

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
		slog.Warn("keep: non-oidc identity received in oidc-verify mode — directory claims stripped",
			"user_id", id.UserID,
			"source", id.SourceType,
		)
		return shared.Principal{
			UserID:     id.UserID,
			SourceType: id.SourceType,
		}, nil
	}

	if id.RawToken == "" {
		return shared.Principal{}, fmt.Errorf("oidc identity missing raw token")
	}

	keyFn := func(token *jwt.Token) (interface{}, error) {
		return n.keyFuncCtx(ctx, token)
	}
	token, err := jwt.Parse(id.RawToken, keyFn)
	if err != nil {
		return shared.Principal{}, fmt.Errorf("verify oidc token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return shared.Principal{}, fmt.Errorf("invalid oidc token claims")
	}

	iss, _ := claims.GetIssuer()
	if n.issuer != "" && iss != n.issuer {
		return shared.Principal{}, fmt.Errorf("oidc token issuer %q does not match configured issuer %q", iss, n.issuer)
	}

	sub, err := claims.GetSubject()
	if err != nil {
		return shared.Principal{}, fmt.Errorf("parse oidc token subject: %w", err)
	}
	if sub == "" {
		return shared.Principal{}, fmt.Errorf("oidc token missing sub claim")
	}

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

	if n.maxTokenAgeSecs > 0 {
		iat, iatErr := claims.GetIssuedAt()
		if iatErr != nil {
			return shared.Principal{}, fmt.Errorf("oidc token iat claim invalid (required when max_token_age_secs is set): %w", iatErr)
		}
		if iat == nil {
			return shared.Principal{}, fmt.Errorf("oidc token missing iat claim (required when max_token_age_secs is set)")
		}
		age := time.Since(iat.Time)
		maxAge := time.Duration(n.maxTokenAgeSecs) * time.Second
		if age > maxAge {
			return shared.Principal{}, fmt.Errorf("oidc token age %v exceeds max allowed age %v", age.Round(time.Second), maxAge)
		}
	}

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

	preferredUsername, _ := claims["preferred_username"].(string)
	acr, _ := claims["acr"].(string)

	var expUnix int64
	if exp != nil {
		expUnix = exp.Unix()
	}

	return shared.Principal{
		UserID:            sub,
		Email:             email,
		DisplayName:       displayName,
		Groups:            groups,
		Roles:             roles,
		Department:        dept,
		AuthMethod:        amr,
		PreferredUsername: preferredUsername,
		ACR:               acr,
		TokenExpiry:       expUnix,
		SourceType:        id.SourceType,
	}, nil
}

func (n *oidcVerifyingNormalizer) keyFuncCtx(ctx context.Context, token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("missing kid in token header")
	}

	keys, err := n.getJWKS(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}

	for _, k := range keys.Keys {
		if k.Kid == kid {
			return n.buildRSAPublicKey(k)
		}
	}

	slog.Info("JWKS kid miss; forcing immediate refresh", "kid", kid)
	keys, err = n.getJWKS(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("refresh JWKS: %w", err)
	}

	for _, k := range keys.Keys {
		if k.Kid == kid {
			return n.buildRSAPublicKey(k)
		}
	}

	reason := fmt.Sprintf("kid %q not found in JWKS after refresh; token may be expired or issued by a restarted IdP", kid)
	return nil, &shared.IdentityVerificationError{Reason: reason}
}

func (n *oidcVerifyingNormalizer) buildRSAPublicKey(k jwk) (*rsa.PublicKey, error) {
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

func (n *oidcVerifyingNormalizer) getJWKS(ctx context.Context, force bool) (*jwks, error) {
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

	if !force && n.jwks != nil && time.Since(n.last) < 1*time.Hour {
		return n.jwks, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build JWKS request: %w", err)
	}
	resp, err := n.httpClient.Do(req)
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

// buildIdentityNormalizer constructs the configured IdentityNormalizer using the global registry.
func buildIdentityNormalizer(cfg *IdentityConfig) (IdentityNormalizer, error) {
	return identity.Build(cfg.Normalizer)
}
