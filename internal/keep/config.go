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
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
	identity "github.com/paclabsnet/PortcullisMCP/internal/shared/identity"
)

// SecretAllowlist lists the config fields eligible for vault:// and other
// restricted secret URI schemes. envvar:// and filevar:// may be used on any field.
var SecretAllowlist = []string{
	"server.endpoints.main.tls.cert",
	"server.endpoints.main.tls.key",
	"server.endpoints.main.tls.client_ca",
	"server.endpoints.main.auth.credentials.bearer_token",
	"responsibility.issuance.signing_key",
}

// LoadConfig reads, parses, resolves secrets in, and validates a keep config file.
func LoadConfig(ctx context.Context, path string) (Config, error) {
	// Use *Config so Validate() can populate derived fields.
	cfg, err := cfgloader.Load[*Config](ctx, path, SecretAllowlist)
	if err != nil {
		return Config{}, err
	}
	return *cfg, nil
}

// Config holds the full portcullis-keep configuration loaded from keep.yaml.
type Config struct {
	Mode           string                     `yaml:"mode"`
	Server         cfgloader.ServerConfig     `yaml:"server"`
	Identity       IdentityConfig             `yaml:"identity"`
	Peers          PeersConfig                `yaml:"peers"`
	Responsibility ResponsibilityConfig       `yaml:"responsibility"`
	Operations     cfgloader.OperationsConfig `yaml:"operations"`

	// Derived / internal use only
	DecisionLog cfgloader.DecisionLogConfig `yaml:"-"`
	Limits      LimitsConfig                `yaml:"-"`
}

// ResponsibilityConfig defines the specialized duty of Portcullis-Keep.
type ResponsibilityConfig struct {
	Policy   PolicyConfig     `yaml:"policy"`
	Backends []BackendConfig  `yaml:"mcp_backends"`
	Issuance IssuanceConfig   `yaml:"issuance"`
	Workflow EscalationConfig `yaml:"workflow"`
	Admin    AdminConfig      `yaml:"admin"`
}

// IssuanceConfig holds signing logic for escalation requests.
type IssuanceConfig struct {
	SigningKey string `yaml:"signing_key"`
	TTL        int    `yaml:"ttl"`
}

// PeersConfig defines outbound connectivity to other Portcullis services.
type PeersConfig struct {
	Guard cfgloader.GuardPeerConfig `yaml:"guard"`
}

// Validate returns an error if the configuration contains invalid values.
func (c *Config) Validate() error {
	if c.Mode == "" {
		c.Mode = cfgloader.ModeProduction
	}

	if c.Mode == cfgloader.ModeProduction {
		if c.Identity.Strategy == "passthrough" {
			return fmt.Errorf("identity.strategy \"passthrough\" is not allowed in production mode")
		}
		if c.Responsibility.Policy.Strategy == "noop" {
			return fmt.Errorf("policy.strategy \"noop\" is not allowed in production mode")
		}
		if val, ok := c.Identity.Config["allow_insecure_jwks_url"]; ok {
			if b, ok := val.(bool); ok && b {
				return fmt.Errorf("identity.config.allow_insecure_jwks_url is not allowed in production mode")
			}
		}

		for name, ep := range c.Server.Endpoints {
			if ep.Auth.Type == "none" {
				return fmt.Errorf("auth.type \"none\" for endpoint %q is not allowed in production mode", name)
			}
			if !cfgloader.IsLoopback(ep.Listen) && !ep.IsSecure() {
				return fmt.Errorf("TLS is required for non-loopback endpoint %q in production mode", name)
			}
		}
	}

	// 1. Validate Main Endpoint
	if _, ok := c.Server.Endpoints["main"]; !ok {
		return fmt.Errorf("server.endpoints.main is required")
	}

	// 2. Decode Identity
	if err := c.Identity.Validate(); err != nil {
		return err
	}

	// 3. Decode Policy
	if err := c.Responsibility.Policy.Validate(); err != nil {
		return err
	}

	// 4. Decode Workflow (Escalation)
	if err := c.Responsibility.Workflow.Validate(); err != nil {
		return err
	}

	// 5. Decode Operations.Limits
	if c.Operations.Limits != nil {
		if err := mapstructure.Decode(c.Operations.Limits, &c.Limits); err != nil {
			return fmt.Errorf("decode operations.limits: %w", err)
		}
	}
	c.Limits.ApplyDefaults()

	// 6. Map DecisionLog
	if logCfg, ok := c.Operations.Storage.Config["decision_log"]; ok {
		if err := mapstructure.Decode(logCfg, &c.DecisionLog); err != nil {
			return fmt.Errorf("decode operations.storage.config.decision_log: %w", err)
		}
	}

	return nil
}

type IdentityConfig struct {
	Strategy string         `yaml:"strategy"` // "passthrough" | "oidc-verify"
	Config   map[string]any `yaml:"config"`

	// Derived
	Normalizer identity.NormalizerConfig `yaml:"-"`
}

func (c *IdentityConfig) Validate() error {
	if c.Strategy == "" {
		return fmt.Errorf("identity.strategy is required")
	}

	if c.Config != nil {
		switch c.Strategy {
		case "oidc-verify":
			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				Result:  &c.Normalizer.OIDCVerify,
				TagName: "yaml",
			})
			if err != nil {
				return err
			}
			if err := decoder.Decode(c.Config); err != nil {
				return fmt.Errorf("decode identity.config for oidc-verify: %w", err)
			}
		case "passthrough":
			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				Result:  &c.Normalizer,
				TagName: "yaml",
			})
			if err != nil {
				return err
			}
			if err := decoder.Decode(c.Config); err != nil {
				return fmt.Errorf("decode identity.config for passthrough: %w", err)
			}
		}
	}

	// Ensure Normalizer field is set after any possible overwrites from Decode.
	c.Normalizer.Normalizer = c.Strategy

	return c.Normalizer.Validate()
}

type PolicyConfig struct {
	Strategy string         `yaml:"strategy"` // "opa" | "noop"
	Config   map[string]any `yaml:"config"`

	// Derived
	OPA OPAConfig `yaml:"-"`
}

type OPAConfig struct {
	Endpoint string `yaml:"endpoint" mapstructure:"endpoint"`
}

func (c *PolicyConfig) Validate() error {
	if c.Config != nil {
		if err := mapstructure.Decode(c.Config, &c.OPA); err != nil {
			return fmt.Errorf("decode policy.config: %w", err)
		}
	}
	if c.Strategy != "noop" && c.OPA.Endpoint == "" {
		return fmt.Errorf("policy.config.endpoint is required when policy.strategy is not \"noop\"")
	}
	return nil
}

type EscalationConfig struct {
	Strategy string         `yaml:"strategy"` // "servicenow" | "webhook" | "url" | "noop"
	Config   map[string]any `yaml:"config"`

	// Derived
	ServiceNow ServiceNowConfig  `yaml:"-"`
	Webhook    WebhookConfig     `yaml:"-"`
	URL        URLWorkflowConfig `yaml:"-"`
}

func (c *EscalationConfig) Validate() error {
	if c.Config != nil {
		switch c.Strategy {
		case "servicenow":
			if err := mapstructure.Decode(c.Config, &c.ServiceNow); err != nil {
				return fmt.Errorf("decode escalation.config for servicenow: %w", err)
			}
		case "webhook":
			if err := mapstructure.Decode(c.Config, &c.Webhook); err != nil {
				return fmt.Errorf("decode escalation.config for webhook: %w", err)
			}
		case "url":
			if err := mapstructure.Decode(c.Config, &c.URL); err != nil {
				return fmt.Errorf("decode escalation.config for url: %w", err)
			}
		}
	}

	switch c.Strategy {
	case "", "noop", "url", "servicenow", "webhook":
		// valid
	default:
		return fmt.Errorf("invalid escalation.strategy %q: must be \"noop\", \"url\", \"servicenow\", or \"webhook\"", c.Strategy)
	}
	if c.Strategy == "servicenow" && c.ServiceNow.Instance == "" {
		return fmt.Errorf("escalation.config.instance is required when strategy is \"servicenow\"")
	}
	if c.Strategy == "webhook" && c.Webhook.URL == "" {
		return fmt.Errorf("escalation.config.url is required when strategy is \"webhook\"")
	}
	return nil
}

type BackendConfig struct {
	Name                  string            `yaml:"name"`
	Type                  string            `yaml:"type"`    // "stdio" | "http" | "sse"
	Command               string            `yaml:"command"` // for stdio
	Args                  []string          `yaml:"args"`
	Env                   map[string]string `yaml:"env"`
	URL                   string            `yaml:"url"` // for http
	AllowPrivateAddresses bool              `yaml:"allow_private_addresses"`
	ToolMap               map[string]string `yaml:"tool_map"`
}

type AdminConfig struct {
	Token string `yaml:"token"`
}

type ServiceNowConfig struct {
	Instance      string `yaml:"instance" mapstructure:"instance"`
	CredentialEnv string `yaml:"credential_env" mapstructure:"credential_env"`
}

type WebhookConfig struct {
	URL     string            `yaml:"url" mapstructure:"url"`
	Headers map[string]string `yaml:"headers" mapstructure:"headers"`
}

type URLWorkflowConfig struct {
	Endpoints cfgloader.GuardEndpoints `yaml:"endpoints" mapstructure:"endpoints"`
}

type SigningConfig = shared.SigningConfig

// LimitsConfig controls request body and field length limits for Keep.
// Zero values are replaced with service defaults by ApplyDefaults.
type LimitsConfig struct {
	MaxRequestBodyBytes int `yaml:"max_request_body_bytes" mapstructure:"max_request_body_bytes"` // default: 1048576 (1 MB)
	MaxServerNameBytes  int `yaml:"max_server_name_bytes" mapstructure:"max_server_name_bytes"`   // default: 256
	MaxToolNameBytes    int `yaml:"max_tool_name_bytes" mapstructure:"max_tool_name_bytes"`       // default: 256
	MaxUserIDBytes      int `yaml:"max_user_id_bytes" mapstructure:"max_user_id_bytes"`           // default: 512
	MaxTraceIDBytes     int `yaml:"max_trace_id_bytes" mapstructure:"max_trace_id_bytes"`         // default: 128
	MaxSessionIDBytes   int `yaml:"max_session_id_bytes" mapstructure:"max_session_id_bytes"`     // default: 128
	MaxReasonBytes      int `yaml:"max_reason_bytes" mapstructure:"max_reason_bytes"`             // default: 4096
	MaxLogBatchSize     int `yaml:"max_log_batch_size" mapstructure:"max_log_batch_size"`         // default: 1000
}

// ApplyDefaults fills any zero-value fields with their service defaults.
func (l *LimitsConfig) ApplyDefaults() {
	if l.MaxRequestBodyBytes == 0 {
		l.MaxRequestBodyBytes = 1 << 20 // 1 MB
	}
	if l.MaxServerNameBytes == 0 {
		l.MaxServerNameBytes = 256
	}
	if l.MaxToolNameBytes == 0 {
		l.MaxToolNameBytes = 256
	}
	if l.MaxUserIDBytes == 0 {
		l.MaxUserIDBytes = 512
	}
	if l.MaxTraceIDBytes == 0 {
		l.MaxTraceIDBytes = 128
	}
	if l.MaxSessionIDBytes == 0 {
		l.MaxSessionIDBytes = 128
	}
	if l.MaxReasonBytes == 0 {
		l.MaxReasonBytes = 4096
	}
	if l.MaxLogBatchSize == 0 {
		l.MaxLogBatchSize = 1000
	}
}
