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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
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

	identity.Register("hmac-verify", func(cfg identity.NormalizerConfig) (identity.Normalizer, error) {
		hcfg := cfg.HMACVerify
		if hcfg.Secret == "" {
			return nil, fmt.Errorf("normalizer hmac-verify requires identity.hmac_verify.secret to be set")
		}
		alg := strings.ToUpper(hcfg.Algorithm)
		if alg == "" {
			alg = "HS256"
		}
		var method jwt.SigningMethod
		switch alg {
		case "HS256":
			method = jwt.SigningMethodHS256
		case "HS384":
			method = jwt.SigningMethodHS384
		case "HS512":
			method = jwt.SigningMethodHS512
		default:
			return nil, fmt.Errorf("normalizer hmac-verify: unsupported algorithm %q; must be HS256, HS384, or HS512", hcfg.Algorithm)
		}
		return &hmacVerifyingNormalizer{
			method:             method,
			secret:             []byte(hcfg.Secret),
			issuer:             hcfg.Issuer,
			audiences:          hcfg.Audiences,
			allowMissingExpiry: hcfg.AllowMissingExpiry,
			maxTokenAgeSecs:    hcfg.MaxTokenAgeSecs,
		}, nil
	})
}

// hmacVerifyingNormalizer validates HMAC-signed JWT token claims before forwarding to the PDP.
type hmacVerifyingNormalizer struct {
	method             jwt.SigningMethod
	secret             []byte
	issuer             string
	audiences          []string
	allowMissingExpiry bool
	maxTokenAgeSecs    int

	// Optional webhook delegation (set by initNormalizerWebhook).
	webhook     *NormalizationClient
	cache       PrincipalCacher
	normCfg     identity.NormalizerConfig
	allowClaims []string
	denyClaims  []string
}

func (n *hmacVerifyingNormalizer) Normalize(ctx context.Context, id shared.UserIdentity) (shared.Principal, error) {
	if id.SourceType != "oidc" && id.SourceType != "hmac" {
		slog.Warn("keep: unexpected identity source in hmac-verify mode — directory claims stripped",
			"user_id", id.UserID,
			"source", id.SourceType,
		)
		return shared.Principal{
			UserID:     id.UserID,
			SourceType: id.SourceType,
		}, nil
	}

	if id.RawToken == "" {
		return shared.Principal{}, fmt.Errorf("hmac identity missing raw token")
	}

	token, err := jwt.Parse(id.RawToken, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != n.method.Alg() {
			return nil, fmt.Errorf("hmac token uses algorithm %q but normalizer requires %q", token.Method.Alg(), n.method.Alg())
		}
		return n.secret, nil
	})
	if err != nil {
		return shared.Principal{}, fmt.Errorf("verify hmac token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return shared.Principal{}, fmt.Errorf("invalid hmac token claims")
	}

	iss, _ := claims.GetIssuer()
	if n.issuer != "" && iss != n.issuer {
		return shared.Principal{}, fmt.Errorf("hmac token issuer %q does not match configured issuer %q", iss, n.issuer)
	}

	sub, err := claims.GetSubject()
	if err != nil {
		return shared.Principal{}, fmt.Errorf("parse hmac token subject: %w", err)
	}
	if sub == "" {
		return shared.Principal{}, fmt.Errorf("hmac token missing sub claim")
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
			return shared.Principal{}, fmt.Errorf("hmac token audience mismatch (aud=%v, expected=%v)", aud, n.audiences)
		}
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		return shared.Principal{}, fmt.Errorf("parse hmac token expiry: %w", err)
	}
	if exp == nil {
		if !n.allowMissingExpiry {
			return shared.Principal{}, fmt.Errorf("hmac token missing exp claim (required by default)")
		}
	} else if time.Now().After(exp.Time) {
		return shared.Principal{}, fmt.Errorf("hmac token is expired (exp=%v)", exp.Time)
	}

	if n.maxTokenAgeSecs > 0 {
		iat, iatErr := claims.GetIssuedAt()
		if iatErr != nil {
			return shared.Principal{}, fmt.Errorf("hmac token iat claim invalid (required when max_token_age_secs is set): %w", iatErr)
		}
		if iat == nil {
			return shared.Principal{}, fmt.Errorf("hmac token missing iat claim (required when max_token_age_secs is set)")
		}
		age := time.Since(iat.Time)
		maxAge := time.Duration(n.maxTokenAgeSecs) * time.Second
		if age > maxAge {
			return shared.Principal{}, fmt.Errorf("hmac token age %v exceeds max allowed age %v", age.Round(time.Second), maxAge)
		}
	}

	var expUnix int64
	if exp != nil {
		expUnix = exp.Unix()
	}

	// Webhook delegation: if configured, replace default claim extraction.
	if n.webhook != nil {
		return n.normalizeViaWebhook(ctx, id.RawToken, map[string]any(claims), id.SourceType, expUnix)
	}

	var email string
	if v, ok := claims["email"].(string); ok {
		email = v
	}
	var displayName string
	if v, ok := claims["name"].(string); ok {
		displayName = v
	}

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

	var dept string
	if v, ok := claims["department"].(string); ok {
		dept = v
	}

	var amr []string
	if a, ok := claims["amr"].([]any); ok {
		for _, v := range a {
			if s, ok := v.(string); ok {
				amr = append(amr, s)
			}
		}
	}

	var preferredUsername string
	if v, ok := claims["preferred_username"].(string); ok {
		preferredUsername = v
	}
	var acr string
	if v, ok := claims["acr"].(string); ok {
		acr = v
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

// normalizeViaWebhook implements the cache→filter→webhook→validate flow shared
// by both HMAC and OIDC normalizers.
func (n *hmacVerifyingNormalizer) normalizeViaWebhook(ctx context.Context, rawToken string, claims map[string]any, sourceType string, expUnix int64) (shared.Principal, error) {
	cacheKey := tokenCacheKey(rawToken)
	if n.cache != nil {
		if cached, ok := n.cache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	filtered := identity.FilterClaims(claims, n.allowClaims, n.denyClaims)
	p, err := n.webhook.Normalize(ctx, filtered)
	if err != nil {
		return shared.Principal{}, fmt.Errorf("normalization webhook: %w", err)
	}

	if err := identity.ValidatePrincipal(p, n.normCfg); err != nil {
		return shared.Principal{}, &NormalizationValidationError{Reason: err.Error()}
	}

	p.SourceType = sourceType
	if expUnix != 0 && p.TokenExpiry == 0 {
		p.TokenExpiry = expUnix
	}

	if n.cache != nil && n.normCfg.CacheTTL > 0 {
		n.cache.Add(cacheKey, p, time.Duration(n.normCfg.CacheTTL)*time.Second)
	}
	return p, nil
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

	// Optional webhook delegation (set by initNormalizerWebhook).
	webhook     *NormalizationClient
	cache       PrincipalCacher
	normCfg     identity.NormalizerConfig
	allowClaims []string
	denyClaims  []string
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

	var expUnix int64
	if exp != nil {
		expUnix = exp.Unix()
	}

	// Webhook delegation: if configured, replace default claim extraction.
	if n.webhook != nil {
		return n.normalizeViaWebhook(ctx, id.RawToken, map[string]any(claims), id.SourceType, expUnix)
	}

	var email string
	if v, ok := claims["email"].(string); ok {
		email = v
	}
	var displayName string
	if v, ok := claims["name"].(string); ok {
		displayName = v
	}

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

	var dept string
	if v, ok := claims["department"].(string); ok {
		dept = v
	}

	var amr []string
	if a, ok := claims["amr"].([]any); ok {
		for _, v := range a {
			if s, ok := v.(string); ok {
				amr = append(amr, s)
			}
		}
	}

	var preferredUsername string
	if v, ok := claims["preferred_username"].(string); ok {
		preferredUsername = v
	}
	var acr string
	if v, ok := claims["acr"].(string); ok {
		acr = v
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

// normalizeViaWebhook implements the cache→filter→webhook→validate flow for
// the OIDC normalizer.
func (n *oidcVerifyingNormalizer) normalizeViaWebhook(ctx context.Context, rawToken string, claims map[string]any, sourceType string, expUnix int64) (shared.Principal, error) {
	cacheKey := tokenCacheKey(rawToken)
	if n.cache != nil {
		if cached, ok := n.cache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	filtered := identity.FilterClaims(claims, n.allowClaims, n.denyClaims)
	p, err := n.webhook.Normalize(ctx, filtered)
	if err != nil {
		return shared.Principal{}, fmt.Errorf("normalization webhook: %w", err)
	}

	if err := identity.ValidatePrincipal(p, n.normCfg); err != nil {
		return shared.Principal{}, &NormalizationValidationError{Reason: err.Error()}
	}

	p.SourceType = sourceType
	if expUnix != 0 && p.TokenExpiry == 0 {
		p.TokenExpiry = expUnix
	}

	if n.cache != nil && n.normCfg.CacheTTL > 0 {
		n.cache.Add(cacheKey, p, time.Duration(n.normCfg.CacheTTL)*time.Second)
	}
	return p, nil
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

// NormalizationValidationError is returned when a normalization webhook responds
// successfully but the returned Principal fails validation (e.g. missing user_id,
// oversized group names). Keep maps this to 403 Forbidden — the request is
// structurally valid but the identity cannot be accepted as configured.
// Contrast with a webhook timeout or 5xx, which maps to 503.
type NormalizationValidationError struct {
	Reason string
}

func (e *NormalizationValidationError) Error() string {
	return "normalization webhook response invalid: " + e.Reason
}

// tokenCacheKey returns a hex-encoded SHA-256 hash of rawToken for use as a
// cache key. Using the hash rather than the raw token avoids retaining the
// full credential string in memory as a map key.
func tokenCacheKey(rawToken string) string {
	h := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(h[:])
}

// buildIdentityNormalizer constructs the configured IdentityNormalizer using the global registry.
func buildIdentityNormalizer(cfg *IdentityConfig) (IdentityNormalizer, error) {
	return identity.Build(cfg.Normalizer)
}

// initNormalizerWebhook injects a NormalizationClient and PrincipalCacher into
// the normalizer when peers.normalization.endpoint is configured. It is a
// no-op when peers is nil or the endpoint is empty.
//
// The cache backend is selected from storage.Backend:
//   - "redis" — shared Redis cache suitable for clustered Keep deployments.
//   - "memory" or "" — in-process LRU cache (default; suitable for single-instance).
func initNormalizerWebhook(ctx context.Context, n IdentityNormalizer, peers *PeersConfig, normCfg identity.NormalizerConfig, storage cfgloader.StorageConfig, mode string) (IdentityNormalizer, error) {
	if peers == nil || peers.Normalization.Endpoint == "" {
		return n, nil
	}

	client, err := newNormalizationClient(peers.Normalization, mode)
	if err != nil {
		return nil, fmt.Errorf("init normalization webhook: %w", err)
	}

	var cache PrincipalCacher
	if normCfg.CacheTTL > 0 {
		cache, err = buildPrincipalCache(ctx, storage, normCfg)
		if err != nil {
			return nil, fmt.Errorf("init normalization cache: %w", err)
		}
	}

	allowClaims := peers.Normalization.AllowClaims
	denyClaims := peers.Normalization.DenyClaims

	switch typed := n.(type) {
	case *oidcVerifyingNormalizer:
		typed.webhook = client
		typed.cache = cache
		typed.normCfg = normCfg
		typed.allowClaims = allowClaims
		typed.denyClaims = denyClaims
	case *hmacVerifyingNormalizer:
		typed.webhook = client
		typed.cache = cache
		typed.normCfg = normCfg
		typed.allowClaims = allowClaims
		typed.denyClaims = denyClaims
	default:
		slog.Warn("keep: peers.normalization.endpoint is configured but the identity strategy does not support webhook normalization; webhook is inactive",
			"strategy", fmt.Sprintf("%T", n),
			"endpoint", peers.Normalization.Endpoint)
	}

	return n, nil
}

// buildPrincipalCache constructs the PrincipalCacher selected by storage.Backend.
func buildPrincipalCache(ctx context.Context, storage cfgloader.StorageConfig, normCfg identity.NormalizerConfig) (PrincipalCacher, error) {
	switch storage.Backend {
	case "redis":
		var redisCfg RedisConfig
		if err := mapstructure.Decode(storage.Config, &redisCfg); err != nil {
			return nil, fmt.Errorf("decode redis config: %w", err)
		}
		redisClient, err := newKeepRedisClient(ctx, redisCfg)
		if err != nil {
			return nil, err
		}
		return NewRedisPrincipalCache(redisClient, redisCfg.KeyPrefix), nil
	case "memory", "":
		maxEntries := normCfg.CacheMaxEntries
		if maxEntries <= 0 {
			maxEntries = 1000
		}
		return NewPrincipalCache(maxEntries), nil
	default:
		return nil, fmt.Errorf("unknown storage backend %q for normalization cache: must be \"memory\" or \"redis\"", storage.Backend)
	}
}
