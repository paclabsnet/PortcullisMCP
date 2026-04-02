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
	"github.com/paclabsnet/PortcullisMCP/internal/shared/tlsutil"
)

// SecretAllowlist lists the config fields eligible for vault:// and other
// restricted secret URI schemes. envvar:// and filevar:// may be used on any field.
var SecretAllowlist = []string{
	"auth.bearer_token",
	"keep.pending_escalation_request_signing_key",
	"escalation_token_signing.key",
	"token_store.redis.password",
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
	if c.Auth.BearerToken == "" && c.Auth.Mtls.ClientCA == "" && !c.Auth.AllowUnauthenticated {
		return fmt.Errorf("auth.bearer_token or auth.mtls.client_ca is required; to allow unauthenticated token API access (development only) set auth.allow_unauthenticated: true")
	}
	switch c.TokenStore.Backend {
	case "", "memory":
		// no extra fields required
	case "redis":
		if c.TokenStore.Redis.Addr == "" {
			return fmt.Errorf("token_store.redis.addr is required when token_store.backend is \"redis\"")
		}
	default:
		return fmt.Errorf("token_store.backend must be \"memory\" or \"redis\", got %q", c.TokenStore.Backend)
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

// MtlsConfig holds the CA certificate used to verify Gate client certificates
// on the API listener. When set, the API listener requests client certificates
// and verifies them against this CA; the machineAuth middleware grants access
// when a valid certificate is presented.
type MtlsConfig struct {
	ClientCA string `yaml:"client_ca"`
}

// AuthConfig controls authentication for the API listener endpoints.
// Authentication is checked in order: mTLS peer cert, Bearer token,
// allow_unauthenticated nag-ware, or 401.
type AuthConfig struct {
	BearerToken          string     `yaml:"bearer_token"`
	AllowUnauthenticated bool       `yaml:"allow_unauthenticated"`
	Mtls                 MtlsConfig `yaml:"mtls"`
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

// TokenStoreConfig selects and configures the backing store for pending
// escalation requests and unclaimed escalation tokens.
type TokenStoreConfig struct {
	// Backend selects the store implementation.
	// "memory" (default) uses an in-process map; data is lost on restart.
	// "redis" uses a Redis server; data persists across restarts and is
	// shared across multiple Guard instances for HA deployments.
	Backend string `yaml:"backend"`

	// TTL is the default lifetime (in seconds) for unclaimed tokens when no
	// expiry can be parsed from the token itself (default: 3600 = 1 hour).
	TTL int `yaml:"ttl"`

	// CleanupInterval is how often (in seconds) the in-memory store scans for
	// and removes expired entries (default: 300 = 5 minutes).
	// Has no effect when backend is "redis" (Redis TTL handles expiry).
	CleanupInterval int `yaml:"cleanup_interval"`

	// Redis holds connection settings used when backend is "redis".
	Redis RedisConfig `yaml:"redis"`
}

// RedisConfig holds connection and security settings for the Redis token store.
type RedisConfig struct {
	// Addr is the Redis server address in "host:port" form (required when
	// token_store.backend is "redis").
	Addr string `yaml:"addr"`

	// Password is the Redis AUTH password.  Leave empty if Redis is not
	// password-protected.  Supports vault:// and envvar:// secret URIs.
	Password string `yaml:"password"`

	// DB selects the Redis logical database (0-based, default 0).
	DB int `yaml:"db"`

	// TLSEnabled enables TLS for the Redis connection (e.g. Redis Enterprise,
	// Upstash, or any Redis deployment with TLS termination).
	TLSEnabled bool `yaml:"tls_enabled"`

	// TLSSkipVerify disables server certificate verification.
	// For development with self-signed certs only; never use in production.
	TLSSkipVerify bool `yaml:"tls_skip_verify"`

	// TLSCACert is an optional path to a PEM file containing the CA certificate
	// used to verify the Redis server's TLS certificate.  If empty, the system
	// certificate pool is used.
	TLSCACert string `yaml:"tls_ca_cert"`

	// KeyPrefix is prepended to every Redis key Guard writes.
	// Defaults to "portcullis:guard:".  Override when sharing a Redis instance
	// across multiple environments.
	KeyPrefix string `yaml:"key_prefix"`
}

// ListenConfig controls the network addresses and TLS settings for Guard's two listeners.
// UIAddress serves the human-facing approval UI (/approve).
// APIAddress serves the machine-to-machine API (/token/*, /pending).
type ListenConfig struct {
	UIAddress  string            `yaml:"ui_address"`
	UITLS      tlsutil.TLSConfig `yaml:"ui_tls"`
	APIAddress string            `yaml:"api_address"`
	APITLS     tlsutil.TLSConfig `yaml:"api_tls"`
}

// Validate returns an error if the listen config contains invalid values.
func (c ListenConfig) Validate() error {
	if c.UIAddress == "" {
		return fmt.Errorf("listen.ui_address is required")
	}
	if c.APIAddress == "" {
		return fmt.Errorf("listen.api_address is required")
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
