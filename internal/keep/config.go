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
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	telemetrycfg "github.com/paclabsnet/PortcullisMCP/internal/telemetry"
)

// Config holds the full portcullis-keep configuration loaded from keep.yaml.
type Config struct {
	Listen                   ListenConfig             `yaml:"listen"`
	PDP                      PDPConfig                `yaml:"pdp"`
	Backends                 map[string]BackendConfig `yaml:"backends"`
	Escalation               EscalationConfig         `yaml:"escalation"`
	DecisionLog              DecisionLogConfig        `yaml:"decision_logs"`
	EscalationRequestSigning SigningConfig             `yaml:"escalation_request_signing"`
	Admin                    AdminConfig              `yaml:"admin"`
	Identity                 IdentityConfig           `yaml:"identity"`
	Telemetry                telemetrycfg.Config      `yaml:"telemetry"`
}

// IdentityConfig controls how Keep normalizes UserIdentity claims received from Gate.
type IdentityConfig struct {
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

// AdminConfig holds credentials for the Keep admin API.
type AdminConfig struct {
	Token string `yaml:"token"` // required to call /admin/* endpoints; reference env var with ${VAR}
}

// SigningConfig holds the HMAC key Keep uses to sign escalation request JWTs.
type SigningConfig struct {
	Key string `yaml:"key"` // HMAC secret; reference env var with ${VAR}
	TTL int    `yaml:"ttl"` // JWT TTL in seconds (default: 3600)
}

type ListenConfig struct {
	Address string     `yaml:"address"`
	TLS     TLSConfig  `yaml:"tls"`
	Auth    AuthConfig `yaml:"auth"`
}

type TLSConfig struct {
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	ClientCA string `yaml:"client_ca"` // non-empty = require mTLS from gate
}

type AuthConfig struct {
	BearerToken string `yaml:"bearer_token"` // optional shared secret for bearer auth
}

type PDPConfig struct {
	Type     string `yaml:"type"`     // "opa"
	Endpoint string `yaml:"endpoint"` // OPA REST API URL
}

type BackendConfig struct {
	Type    string            `yaml:"type"`    // "stdio" | "http" (Streamable HTTP) | "sse" (legacy SSE)
	Command string            `yaml:"command"` // for stdio
	Args    []string          `yaml:"args"`
	Env     map[string]string `yaml:"env"`
	URL     string            `yaml:"url"` // for http

	// AllowPrivateAddresses opts this backend out of the RFC 1918 / loopback /
	// link-local address check. Set to true for backends that are intentionally
	// deployed on internal networks (e.g. Docker Compose, on-premises services).
	// Redirects are still refused regardless of this setting.
	AllowPrivateAddresses bool `yaml:"allow_private_addresses"`
}

type EscalationConfig struct {
	Workflow WorkflowConfig `yaml:"workflow"`
}

type WorkflowConfig struct {
	Type       string            `yaml:"type"` // "servicenow" | "webhook" | "url" | "noop"
	ServiceNow ServiceNowConfig  `yaml:"servicenow"`
	Webhook    WebhookConfig     `yaml:"webhook"`
	URL        URLWorkflowConfig `yaml:"url"`
}

// URLWorkflowConfig is the demo workflow plugin that returns a Guard approval URL
// through the MCP error channel so the user can approve directly.
type URLWorkflowConfig struct {
	GuardURL string `yaml:"guard_url"` // base URL of portcullis-guard, e.g. "https://guard.internal.example.com"
}

type ServiceNowConfig struct {
	Instance      string `yaml:"instance"`
	CredentialEnv string `yaml:"credential_env"`
}

type WebhookConfig struct {
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`
}

type DecisionLogConfig struct {
	Enabled       bool              `yaml:"enabled"`        // whether logging is enabled
	BufferSize    int               `yaml:"buffer_size"`    // channel buffer size (default: 10000)
	FlushInterval int               `yaml:"flush_interval"` // seconds between flushes (default: 5)
	MaxBatchSize  int               `yaml:"max_batch_size"` // max entries per batch (default: 1000)
	URL           string            `yaml:"url"`            // remote endpoint URL
	Headers       map[string]string `yaml:"headers"`        // HTTP headers for remote endpoint
	Console       bool              `yaml:"console"`        // also log to console
}

// Validate returns an error if the configuration contains invalid values.
func (c Config) Validate() error {
	if c.Listen.Address == "" {
		return fmt.Errorf("listen.address is required")
	}
	if c.PDP.Endpoint == "" {
		return fmt.Errorf("pdp.endpoint is required")
	}

	switch c.Identity.Normalizer {
	case "", "strict", "passthrough", "oidc-verify":
		// valid
	default:
		return fmt.Errorf("invalid identity.normalizer %q: must be \"strict\", \"passthrough\", or \"oidc-verify\"", c.Identity.Normalizer)
	}
	if c.Identity.Normalizer == "oidc-verify" {
		if c.Identity.OIDCVerify.Issuer == "" {
			return fmt.Errorf("identity.oidc_verify.issuer is required when normalizer is \"oidc-verify\"")
		}
		if c.Identity.OIDCVerify.JWKSURL == "" {
			return fmt.Errorf("identity.oidc_verify.jwks_url is required when normalizer is \"oidc-verify\"")
		}
	}

	switch c.Escalation.Workflow.Type {
	case "", "noop", "url", "servicenow", "webhook":
		// valid
	default:
		return fmt.Errorf("invalid escalation.workflow.type %q: must be \"noop\", \"url\", \"servicenow\", or \"webhook\"", c.Escalation.Workflow.Type)
	}
	if c.Escalation.Workflow.Type == "servicenow" && c.Escalation.Workflow.ServiceNow.Instance == "" {
		return fmt.Errorf("escalation.workflow.servicenow.instance is required when workflow type is \"servicenow\"")
	}
	if c.Escalation.Workflow.Type == "webhook" && c.Escalation.Workflow.Webhook.URL == "" {
		return fmt.Errorf("escalation.workflow.webhook.url is required when workflow type is \"webhook\"")
	}

	return nil
}

// LoadConfig reads and parses a keep config file, expanding environment variables.
// It uses strict unmarshaling to ensure that unknown or deprecated fields
// cause a configuration error at startup.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	data = shared.ExpandEnvVarsInYAML(data)
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, cfg.Validate()
}
