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
	"sync"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// NormalizerConfig controls how a component normalizes UserIdentity claims
// received from portcullis-gate.
type NormalizerConfig struct {
	// Normalizer selects the identity normalization strategy.
	//   "strict" (default) — OS-sourced identities are stripped to user_id only.
	//                        OIDC-sourced identities pass through unchanged.
	//   "passthrough"      — All identity fields are accepted as-is. Local
	//                        evaluation and sandbox deployments only.
	//   "oidc-verify"      — Rejects expired OIDC tokens and tokens not issued
	//                        by the configured issuer. OS identities are handled
	//                        with strict stripping.
	Normalizer string `yaml:"normalizer"` // "strict" | "passthrough" | "oidc-verify"

	// AcceptForgedIdentities suppresses the per-request warning emitted in
	// passthrough mode. Has no effect on other normalizers.
	AcceptForgedIdentities bool `yaml:"accept_forged_identities"`

	// OIDCVerify holds configuration for the oidc-verify normalizer.
	OIDCVerify OIDCVerifyConfig `yaml:"oidc_verify"`
}

// Validate returns an error if the normalizer config contains invalid values.
func (c NormalizerConfig) Validate() error {
	switch c.Normalizer {
	case "", "strict", "passthrough", "oidc-verify":
		// valid
	default:
		return fmt.Errorf("invalid identity.normalizer %q: must be \"strict\", \"passthrough\", or \"oidc-verify\"", c.Normalizer)
	}
	if c.Normalizer == "oidc-verify" {
		if c.OIDCVerify.Issuer == "" {
			return fmt.Errorf("identity.oidc_verify.issuer is required when normalizer is \"oidc-verify\"")
		}
		if c.OIDCVerify.JWKSURL == "" {
			return fmt.Errorf("identity.oidc_verify.jwks_url is required when normalizer is \"oidc-verify\"")
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
	// verification. Required when normalizer is "oidc-verify".
	JWKSURL string `yaml:"jwks_url"`

	// Audiences is an optional list of allowed audience (aud) values.
	// If provided, the token must contain at least one of these audiences.
	Audiences []string `yaml:"audiences"`

	// AllowMissingExpiry defaults to false. If false (default), OIDC tokens
	// without an expiration (exp) claim will be rejected (fail secure).
	// Set to true only if your Identity Provider does not provide exp claims.
	AllowMissingExpiry bool `yaml:"allow_missing_expiry"`
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
// registry. Returns an error if the normalizer name is unknown or the factory
// returns an error.
func Build(cfg NormalizerConfig) (Normalizer, error) {
	name := cfg.Normalizer
	if name == "" {
		name = "strict"
	}

	registryMu.RLock()
	factory, ok := registry[name]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown identity normalizer %q; supported: strict, passthrough, oidc-verify", name)
	}

	return factory(cfg)
}
