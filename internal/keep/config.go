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

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
	identity "github.com/paclabsnet/PortcullisMCP/internal/shared/identity"
	"github.com/paclabsnet/PortcullisMCP/internal/shared/tlsutil"
	telemetrycfg "github.com/paclabsnet/PortcullisMCP/internal/telemetry"
)

// SecretAllowlist lists the config fields eligible for vault:// and other
// restricted secret URI schemes. envvar:// and filevar:// may be used on any field.
var SecretAllowlist = []string{
	"listen.tls.cert",
	"listen.tls.key",
	"listen.tls.client_ca",
	"listen.auth.bearer_token",
	"admin.token",
	"escalation_request_signing.key",
}

// SigningConfig is an alias for shared.SigningConfig.
// Keep uses it for escalation_request_signing; the canonical definition lives in
// internal/shared so it can be shared with portcullis-guard without duplication.
type SigningConfig = shared.SigningConfig

// LimitsConfig controls request body and field length limits for Keep.
// Zero values are replaced with service defaults by ApplyDefaults.
type LimitsConfig struct {
	MaxRequestBodyBytes int `yaml:"max_request_body_bytes"` // default: 1048576 (1 MB)
	MaxServerNameBytes  int `yaml:"max_server_name_bytes"`  // default: 256
	MaxToolNameBytes    int `yaml:"max_tool_name_bytes"`    // default: 256
	MaxUserIDBytes      int `yaml:"max_user_id_bytes"`      // default: 512
	MaxTraceIDBytes     int `yaml:"max_trace_id_bytes"`     // default: 128
	MaxSessionIDBytes   int `yaml:"max_session_id_bytes"`   // default: 128
	MaxReasonBytes      int `yaml:"max_reason_bytes"`       // default: 4096
	MaxLogBatchSize     int `yaml:"max_log_batch_size"`     // default: 1000
}

// ApplyDefaults fills any zero-value fields with their service defaults.
// Call this once during server initialisation before any request is processed.
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
	Limits                   LimitsConfig             `yaml:"limits"`
}

// IdentityConfig is an alias for identity.NormalizerConfig.
// Keep uses it for the identity.normalizer section of keep.yaml; the canonical
// definition lives in internal/shared/identity so it can be reused by other
// components that perform identity normalization.
type IdentityConfig = identity.NormalizerConfig

// OIDCVerifyConfig is an alias for identity.OIDCVerifyConfig.
// The canonical definition lives in internal/shared/identity.
type OIDCVerifyConfig = identity.OIDCVerifyConfig

// AdminConfig holds credentials for the Keep admin API.
type AdminConfig struct {
	Token string `yaml:"token"` // required to call /admin/* endpoints; reference a secret URI with envvar:// or vault://
}

type ListenConfig struct {
	Address string     `yaml:"address"`
	TLS     TLSConfig  `yaml:"tls"`
	Auth    AuthConfig `yaml:"auth"`
}

// Validate returns an error if the listen config contains invalid values.
func (c ListenConfig) Validate() error {
	if c.Address == "" {
		return fmt.Errorf("listen.address is required")
	}
	return nil
}

// TLSConfig is an alias for tlsutil.TLSConfig.
// The canonical definition lives in internal/shared/tlsutil so it can be
// shared with portcullis-guard without duplication.
type TLSConfig = tlsutil.TLSConfig

type AuthConfig struct {
	BearerToken string `yaml:"bearer_token"` // optional shared secret for bearer auth
}

type PDPConfig struct {
	Type     string `yaml:"type"`     // "opa" | "noop"
	Endpoint string `yaml:"endpoint"` // OPA REST API URL
}

// Validate returns an error if the PDP config contains invalid values.
func (c PDPConfig) Validate() error {
	if c.Type != "noop" && c.Endpoint == "" {
		return fmt.Errorf("pdp.endpoint is required when pdp.type is not \"noop\"")
	}
	return nil
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

	// ToolMap renames tools before presenting them to the agent.
	// Key is the tool's real name on the backend; value is the alias
	// the agent and PDP will see. Aliases must be unique across all backends.
	// Example: {"query_database": "acme_query_database"}
	ToolMap map[string]string `yaml:"tool_map"`
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

// Validate returns an error if the workflow config contains invalid values.
func (c WorkflowConfig) Validate() error {
	switch c.Type {
	case "", "noop", "url", "servicenow", "webhook":
		// valid
	default:
		return fmt.Errorf("invalid escalation.workflow.type %q: must be \"noop\", \"url\", \"servicenow\", or \"webhook\"", c.Type)
	}
	if c.Type == "servicenow" && c.ServiceNow.Instance == "" {
		return fmt.Errorf("escalation.workflow.servicenow.instance is required when workflow type is \"servicenow\"")
	}
	if c.Type == "webhook" && c.Webhook.URL == "" {
		return fmt.Errorf("escalation.workflow.webhook.url is required when workflow type is \"webhook\"")
	}
	return nil
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
	if err := c.Listen.Validate(); err != nil {
		return err
	}
	if err := c.PDP.Validate(); err != nil {
		return err
	}
	if err := c.Identity.Validate(); err != nil {
		return err
	}
	return c.Escalation.Workflow.Validate()
}

// LoadConfig reads, parses, resolves secrets in, and validates a keep config file.
// It uses strict unmarshaling to ensure that unknown or deprecated fields
// cause a configuration error at startup.
func LoadConfig(ctx context.Context, path string) (Config, error) {
	return cfgloader.Load[Config](ctx, path, SecretAllowlist)
}
