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

// Package identity defines the shared identity normalization contract used by
// portcullis-keep. Centralizing these types here ensures that any component
// that participates in identity normalization uses the same configuration
// schema, validation rules, and extension point.
package identity

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// NormalizerConfig controls how a component normalizes UserIdentity claims
// received from portcullis-gate.
type NormalizerConfig struct {
	// Normalizer selects the identity normalization strategy. Required — Keep
	// will not start without an explicit value.
	//   "passthrough"  — All identity fields accepted as-is. Dev, PoC, and
	//                    sandbox deployments only.
	//   "oidc-verify"  — Cryptographically verifies OIDC tokens via JWKS and
	//                    extracts claims from the verified token only.
	//                    Required for all production deployments using RSA-signed tokens.
	//   "hmac-verify"  — Cryptographically verifies HMAC-signed JWTs (HS256/HS384/HS512)
	//                    using a shared secret. Use when the IdP issues symmetric tokens
	//                    (e.g. AWS AgentCore).
	Normalizer string `yaml:"normalizer"` // "passthrough" | "oidc-verify" | "hmac-verify"

	// AcceptForgedIdentities suppresses the per-request warning emitted in
	// passthrough mode. Has no effect on other normalizers.
	AcceptForgedIdentities bool `yaml:"accept_forged_identities"`

	// OIDCVerify holds configuration for the oidc-verify normalizer.
	OIDCVerify OIDCVerifyConfig `yaml:"oidc_verify"`

	// HMACVerify holds configuration for the hmac-verify normalizer.
	// Decoding is handled via mapstructure in keep/config.go, not direct YAML unmarshalling.
	HMACVerify HMACVerifyConfig `yaml:"-"`
}

// Validate returns an error if the normalizer config contains invalid values.
func (c NormalizerConfig) Validate() error {
	switch c.Normalizer {
	case "passthrough", "oidc-verify", "hmac-verify":
		// valid
	case "":
		return fmt.Errorf("identity.normalizer must be set; valid values: \"passthrough\" (dev/PoC only), \"oidc-verify\", \"hmac-verify\"")
	default:
		return fmt.Errorf("invalid identity.normalizer %q: valid values: \"passthrough\" (dev/PoC only), \"oidc-verify\", \"hmac-verify\"", c.Normalizer)
	}
	if c.Normalizer == "oidc-verify" {
		if c.OIDCVerify.Issuer == "" {
			return fmt.Errorf("identity.oidc_verify.issuer is required when normalizer is \"oidc-verify\"")
		}
		if c.OIDCVerify.JWKSURL == "" {
			return fmt.Errorf("identity.oidc_verify.jwks_url is required when normalizer is \"oidc-verify\"")
		}
		if !strings.HasPrefix(c.OIDCVerify.JWKSURL, "https://") && !c.OIDCVerify.AllowInsecureJWKSURL {
			return fmt.Errorf("identity.oidc_verify.jwks_url must use https:// (got %q); set allow_insecure_jwks_url: true to override for non-production use only", c.OIDCVerify.JWKSURL)
		}
	}
	if c.Normalizer == "hmac-verify" {
		if c.HMACVerify.Secret == "" {
			return fmt.Errorf("identity.hmac_verify.secret is required when normalizer is \"hmac-verify\"")
		}
		alg := strings.ToUpper(c.HMACVerify.Algorithm)
		if alg != "" && alg != "HS256" && alg != "HS384" && alg != "HS512" {
			return fmt.Errorf("invalid identity.hmac_verify.algorithm %q: must be HS256, HS384, or HS512", c.HMACVerify.Algorithm)
		}
	}
	return nil
}

// OIDCVerifyConfig holds settings for the oidc-verify identity normalizer.
type OIDCVerifyConfig struct {
	// Issuer is the expected iss claim value, e.g.
	// "https://login.microsoftonline.com/<tenant-id>/v2.0". Required when
	// normalizer is "oidc-verify".
	Issuer string `yaml:"issuer"`

	// JWKSURL is the URL to the issuer's JSON Web Key Set (JWKS) for signature
	// verification. Required when normalizer is "oidc-verify". Must use HTTPS
	// unless allow_insecure_jwks_url is explicitly set to true.
	JWKSURL string `yaml:"jwks_url"`

	// Audiences is an optional list of allowed audience (aud) values.
	// If provided, the token must contain at least one of these audiences.
	Audiences []string `yaml:"audiences"`

	// AllowMissingExpiry defaults to false. If false (default), OIDC tokens
	// without an expiration (exp) claim will be rejected (fail secure).
	// Set to true only if your Identity Provider does not provide exp claims.
	AllowMissingExpiry bool `yaml:"allow_missing_expiry"`

	// AllowInsecureJWKSURL permits an http:// jwks_url. Never set this in
	// production — a plaintext JWKS endpoint allows MITM key substitution,
	// which undermines the entire token verification chain.
	AllowInsecureJWKSURL bool `yaml:"allow_insecure_jwks_url"`

	// MaxTokenAgeSecs is the maximum allowed age of the OIDC token in seconds,
	// measured from the iat (issued-at) claim. 0 means no enforcement.
	// Use this to enforce a short TTL regardless of the token's exp claim.
	MaxTokenAgeSecs int `yaml:"max_token_age_secs"`
}

// HMACVerifyConfig holds settings for the hmac-verify identity normalizer.
type HMACVerifyConfig struct {
	// Secret is the shared secret used for HMAC signature verification.
	// Supports envvar:// and vault:// URIs. Required.
	Secret string `yaml:"secret"`

	// Algorithm specifies the HMAC variant: "HS256", "HS384", or "HS512".
	// Defaults to "HS256" if empty.
	Algorithm string `yaml:"algorithm"`

	// Issuer is the optional expected iss claim value.
	Issuer string `yaml:"issuer"`

	// Audiences is an optional list of allowed audience (aud) values.
	// If provided, the token must contain at least one of these audiences.
	Audiences []string `yaml:"audiences"`

	// AllowMissingExpiry defaults to false. If false, tokens without an exp
	// claim are rejected (fail secure).
	AllowMissingExpiry bool `yaml:"allow_missing_expiry"`

	// MaxTokenAgeSecs is the maximum allowed age of the token in seconds,
	// measured from the iat (issued-at) claim. 0 means no enforcement.
	MaxTokenAgeSecs int `yaml:"max_token_age_secs"`
}

// Normalizer transforms a raw UserIdentity received from portcullis-gate into
// a normalized Principal suitable for forwarding to the PDP.
//
// A non-nil error means the normalizer could not process the identity (e.g.,
// invalid token, misconfigured normalizer). Keep returns 503 in that case.
type Normalizer interface {
	Normalize(ctx context.Context, id shared.UserIdentity) (shared.Principal, error)
}

// NormalizerFactory is a function that creates a Normalizer from the
// provided configuration.
type NormalizerFactory func(cfg NormalizerConfig) (Normalizer, error)

var (
	registryMu sync.RWMutex
	registry   = make(map[string]NormalizerFactory)
)

// Register adds a Normalizer factory to the global registry under the given
// name. It should be called from an init() function in the implementing
// package (e.g., portcullis-keep).
func Register(name string, factory NormalizerFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = factory
}

// Build constructs the Normalizer specified by cfg.Normalizer using the global
// registry. Returns an error if the normalizer name is empty, unknown, or the
// factory returns an error.
func Build(cfg NormalizerConfig) (Normalizer, error) {
	if cfg.Normalizer == "" {
		return nil, fmt.Errorf("identity.normalizer must be set; valid values: \"passthrough\" (dev/PoC only), \"oidc-verify\" (production)")
	}

	registryMu.RLock()
	factory, ok := registry[cfg.Normalizer]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown identity normalizer %q; valid values: \"passthrough\" (dev/PoC only), \"oidc-verify\", \"hmac-verify\"", cfg.Normalizer)
	}

	return factory(cfg)
}
