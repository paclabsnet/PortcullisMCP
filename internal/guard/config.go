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

	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// SecretAllowlist lists the config fields eligible for vault:// and other
// restricted secret URI schemes. envvar:// and filevar:// may be used on any field.
var SecretAllowlist = []string{
	"server.endpoints.token_api.auth.credentials.bearer_token",
	"responsibility.issuance.approval_request_verification_key",
	"responsibility.issuance.signing_key",
	"operations.storage.config.password",
}

// LoadConfig reads, parses, resolves secrets in, and validates a guard config file.
// It returns the config and a PostureReport for startup security attestation.
func LoadConfig(ctx context.Context, path string) (Config, cfgloader.PostureReport, error) {
	cfg, report, err := cfgloader.Load[*Config](ctx, path, SecretAllowlist)
	if err != nil {
		return Config{}, report, err
	}
	return *cfg, report, nil
}

// Config holds the full portcullis-guard configuration.
type Config struct {
	Mode           string                     `yaml:"mode"`
	Server         cfgloader.ServerConfig     `yaml:"server"`
	Identity       cfgloader.IdentityConfig   `yaml:"identity"`
	Peers          PeersConfig                `yaml:"peers"`
	Responsibility ResponsibilityConfig       `yaml:"responsibility"`
	Operations     cfgloader.OperationsConfig `yaml:"operations"`

	// Derived / internal use only
	Limits LimitsConfig `yaml:"-"`
}

// ResponsibilityConfig defines the specialized duty of Portcullis-Guard.
type ResponsibilityConfig struct {
	Issuance  IssuanceConfig  `yaml:"issuance"`
	Interface InterfaceConfig `yaml:"interface"`
}

// IssuanceConfig holds signing logic for approved tokens and request verification.
type IssuanceConfig struct {
	// ApprovalRequestVerificationKey is the HMAC key used to verify requests from Keep.
	ApprovalRequestVerificationKey string `yaml:"approval_request_verification_key"`

	// SigningKey is the HMAC key used to sign issued escalation tokens.
	SigningKey string `yaml:"signing_key"`

	// TokenTTL is the TTL for issued escalation tokens in seconds.
	TokenTTL int `yaml:"token_ttl"`
}

// InterfaceConfig holds UI-specific settings.
type InterfaceConfig struct {
	Templates          string `yaml:"templates"`
	GateManagementPort int    `yaml:"gate_management_port"` // Port shown in UI instructions
}

// PeersConfig defines outbound connectivity to other Portcullis services.
type PeersConfig struct {
	Keep cfgloader.PeerAuth `yaml:"keep"`
}

// Validate returns a PostureReport and an error if the configuration contains invalid values.
func (c *Config) Validate(sources cfgloader.SourceMap) (cfgloader.PostureReport, error) {
	if c.Mode == "" {
		c.Mode = cfgloader.ModeProduction
	}

	if c.Mode == cfgloader.ModeProduction {
		for name, ep := range c.Server.Endpoints {
			if ep.Auth.Type == "none" {
				return cfgloader.PostureReport{}, fmt.Errorf("auth.type \"none\" for endpoint %q is not allowed in production mode", name)
			}
			if !cfgloader.IsLoopback(ep.Listen) && !ep.IsSecure() {
				return cfgloader.PostureReport{}, fmt.Errorf("TLS is required for non-loopback endpoint %q in production mode", name)
			}
		}
	}

	if _, ok := c.Server.Endpoints["approval_ui"]; !ok {
		return cfgloader.PostureReport{}, fmt.Errorf("server.endpoints.approval_ui is required")
	}
	if _, ok := c.Server.Endpoints["token_api"]; !ok {
		return cfgloader.PostureReport{}, fmt.Errorf("server.endpoints.token_api is required")
	}

	if c.Responsibility.Issuance.ApprovalRequestVerificationKey == "" {
		return cfgloader.PostureReport{}, fmt.Errorf("responsibility.issuance.approval_request_verification_key is required")
	}
	if c.Responsibility.Issuance.SigningKey == "" {
		return cfgloader.PostureReport{}, fmt.Errorf("responsibility.issuance.signing_key is required")
	}

	if c.Operations.Limits != nil {
		if err := mapstructure.Decode(c.Operations.Limits, &c.Limits); err != nil {
			return cfgloader.PostureReport{}, fmt.Errorf("decode operations.limits: %w", err)
		}
	}
	c.Limits.ApplyDefaults()

	report := cfgloader.BuildPostureReport(c, sources, SecretAllowlist)

	if c.Mode != cfgloader.ModeProduction {
		report.SetStatus("mode", "WARN", "Use production mode for deployments")
	}
	for name, ep := range c.Server.Endpoints {
		if ep.Auth.Type == "none" {
			report.SetStatus("server.endpoints."+name+".auth.type", "WARN", "Configure authentication for this endpoint in production")
		}
		if !ep.IsSecure() {
			report.SetStatus("server.endpoints."+name+".tls.cert", "WARN", "Enable TLS for this endpoint in production")
		}
	}

	return report, nil
}

// LimitsConfig controls request body, field length, and in-memory map size limits for Guard.
type LimitsConfig struct {
	MaxRequestBodyBytes   int `yaml:"max_request_body_bytes" mapstructure:"max_request_body_bytes"`
	MaxUserIDBytes        int `yaml:"max_user_id_bytes" mapstructure:"max_user_id_bytes"`
	MaxJTIBytes           int `yaml:"max_jti_bytes" mapstructure:"max_jti_bytes"`
	MaxPendingJWTBytes    int `yaml:"max_pending_jwt_bytes" mapstructure:"max_pending_jwt_bytes"`
	MaxScopeOverrideBytes int `yaml:"max_scope_override_bytes" mapstructure:"max_scope_override_bytes"`
	MaxPendingRequests    int `yaml:"max_pending_requests" mapstructure:"max_pending_requests"`
	MaxUnclaimedPerUser   int `yaml:"max_unclaimed_per_user" mapstructure:"max_unclaimed_per_user"`
	MaxUnclaimedTotal     int `yaml:"max_unclaimed_total" mapstructure:"max_unclaimed_total"`
}

func (l *LimitsConfig) ApplyDefaults() {
	if l.MaxRequestBodyBytes == 0 {
		l.MaxRequestBodyBytes = 512 << 10
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

// RedisConfig holds connection and security settings for the Redis token store.
type RedisConfig struct {
	Addr          string `yaml:"addr" mapstructure:"addr"`
	Password      string `yaml:"password" mapstructure:"password"`
	DB            int    `yaml:"db" mapstructure:"db"`
	TLSEnabled    bool   `yaml:"tls_enabled" mapstructure:"tls_enabled"`
	TLSSkipVerify bool   `yaml:"tls_skip_verify" mapstructure:"tls_skip_verify"`
	TLSCACert     string `yaml:"tls_ca_cert" mapstructure:"tls_ca_cert"`
	KeyPrefix     string `yaml:"key_prefix" mapstructure:"key_prefix"`
}

type portcullisClaims struct {
	Reason          string           `json:"reason"`
	ArgRestrictions []map[string]any `json:"arg_restrictions"`
	Tools           []string         `json:"tools"`
	Services        []string         `json:"services"`
}

type escalationTokenClaims struct {
	jwt.RegisteredClaims
	Portcullis portcullisClaims `json:"portcullis"`
}
