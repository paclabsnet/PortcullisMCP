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

package guard

import (
	"context"
	"fmt"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// SecretAllowlist lists the config fields eligible for vault:// and other
// restricted secret URI schemes. envvar:// and filevar:// may be used on any field.
var SecretAllowlist = []string{
	"auth.bearer_token",
	"keep.pending_escalation_request_signing_key",
	"escalation_token_signing.key",
}

// SigningConfig is an alias for shared.SigningConfig.
// Guard uses it for escalation_token_signing; the canonical definition lives in
// internal/shared so it can be shared with portcullis-keep without duplication.
type SigningConfig = shared.SigningConfig

// LoadConfig reads, parses, resolves secrets in, and validates a guard config file.
// It uses strict unmarshaling to ensure that unknown or deprecated fields
// cause a configuration error at startup.
func LoadConfig(ctx context.Context, path string) (Config, error) {
	return cfgloader.Load[Config](ctx, path, SecretAllowlist)
}

// Validate returns an error if the configuration contains invalid values.
func (c Config) Validate() error {
	if err := c.Listen.Validate(); err != nil {
		return err
	}
	if c.Keep.PendingEscalationRequestSigningKey == "" {
		return fmt.Errorf("keep.pending_escalation_request_signing_key is required")
	}
	if c.EscalationTokenSigning.Key == "" {
		return fmt.Errorf("escalation_token_signing.key is required")
	}
	if c.Auth.BearerToken == "" && !c.Auth.AllowUnauthenticated {
		return fmt.Errorf("auth.bearer_token is required; to allow unauthenticated token API access (development only) set auth.allow_unauthenticated: true")
	}
	return nil
}

// Config holds the full portcullis-guard configuration.
type Config struct {
	Listen                       ListenConfig     `yaml:"listen"`
	Keep                         KeepConfig       `yaml:"keep"`
	EscalationTokenSigning       SigningConfig     `yaml:"escalation_token_signing"`
	Templates                    TemplatesConfig  `yaml:"templates"`
	PortcullisGateManagementPort int              `yaml:"portcullis_gate_management_port"` // gate management API port shown in post-approval instructions (default: 7777)
	Auth                         AuthConfig       `yaml:"auth"`
	TokenStore                   TokenStoreConfig `yaml:"token_store"`
	Limits                       LimitsConfig     `yaml:"limits"`
}

// AuthConfig controls authentication for the token API endpoints.
// /token/unclaimed/list and /token/deposit require a valid bearer token.
// /token/claim does not require auth — the JTI is treated as a capability.
type AuthConfig struct {
	BearerToken        string `yaml:"bearer_token"`
	AllowUnauthenticated bool `yaml:"allow_unauthenticated"`
}

// LimitsConfig controls request body, field length, and in-memory map size limits for Guard.
// Zero values are replaced with service defaults by ApplyDefaults.
type LimitsConfig struct {
	MaxRequestBodyBytes   int `yaml:"max_request_body_bytes"`   // default: 524288 (512 KB)
	MaxUserIDBytes        int `yaml:"max_user_id_bytes"`        // default: 512
	MaxJTIBytes           int `yaml:"max_jti_bytes"`            // default: 128
	MaxPendingJWTBytes    int `yaml:"max_pending_jwt_bytes"`    // default: 8192
	MaxScopeOverrideBytes int `yaml:"max_scope_override_bytes"` // default: 16384
	MaxPendingRequests    int `yaml:"max_pending_requests"`     // default: 10000
	MaxUnclaimedPerUser   int `yaml:"max_unclaimed_per_user"`   // default: 10000
	MaxUnclaimedTotal     int `yaml:"max_unclaimed_total"`      // default: 100000
}

// ApplyDefaults fills any zero-value fields with their service defaults.
// Call this once during server initialisation before any request is processed.
func (l *LimitsConfig) ApplyDefaults() {
	if l.MaxRequestBodyBytes == 0 {
		l.MaxRequestBodyBytes = 512 << 10 // 512 KB
	}
	if l.MaxUserIDBytes == 0 {
		l.MaxUserIDBytes = 512
	}
	if l.MaxJTIBytes == 0 {
		l.MaxJTIBytes = 128
	}
	if l.MaxPendingJWTBytes == 0 {
		l.MaxPendingJWTBytes = 8192
	}
	if l.MaxScopeOverrideBytes == 0 {
		l.MaxScopeOverrideBytes = 16384
	}
	if l.MaxPendingRequests == 0 {
		l.MaxPendingRequests = 10_000
	}
	if l.MaxUnclaimedPerUser == 0 {
		l.MaxUnclaimedPerUser = 10_000
	}
	if l.MaxUnclaimedTotal == 0 {
		l.MaxUnclaimedTotal = 100_000
	}
}

// TokenStoreConfig controls the in-memory unclaimed token store.
type TokenStoreConfig struct {
	// TTL is the default lifetime (in seconds) for unclaimed tokens when no
	// expiry can be parsed from the token itself (default: 3600 = 1 hour).
	TTL int `yaml:"ttl"`
	// CleanupInterval is how often (in seconds) Guard scans for and removes
	// expired unclaimed tokens (default: 300 = 5 minutes).
	CleanupInterval int `yaml:"cleanup_interval"`
}

type ListenConfig struct {
	Address string `yaml:"address"`
}

// Validate returns an error if the listen config contains invalid values.
func (c ListenConfig) Validate() error {
	if c.Address == "" {
		return fmt.Errorf("listen.address is required")
	}
	return nil
}

// KeepConfig holds the key Guard uses to verify Keep-signed escalation request JWTs.
type KeepConfig struct {
	PendingEscalationRequestSigningKey string `yaml:"pending_escalation_request_signing_key"` // must match keep.escalation_request_signing.key
}

// TemplatesConfig points to the directory containing approval.html and token.html.
// If Dir is empty, Guard uses its built-in default templates from the installation.
type TemplatesConfig struct {
	Dir string `yaml:"dir"`
}
