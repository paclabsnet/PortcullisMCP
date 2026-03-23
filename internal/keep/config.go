package keep

import (
	"os"

	"gopkg.in/yaml.v3"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
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
}

// IdentityConfig controls how Keep handles the UserIdentity claims sent by Gate.
type IdentityConfig struct {
	// Mode controls how Keep treats incoming identity claims.
	//   "strict" (default) — OS-sourced identities are stripped down to user_id
	//                        only; groups, roles, and other directory claims are
	//                        discarded because Gate cannot verify them locally.
	//   "demo"             — All identity fields are accepted as-is. Intended for
	//                        local evaluation and sandbox use only. Keep logs a
	//                        warning on every request unless AcceptForgedIdentities
	//                        is also true.
	Mode string `yaml:"mode"` // "strict" | "demo"

	// AcceptForgedIdentities suppresses the per-request warning that is emitted
	// in demo mode. Has no effect in strict mode. Set to true only when you
	// intentionally want to test with fabricated identity data and do not want
	// the log noise.
	AcceptForgedIdentities bool `yaml:"accept_forged_identities"`
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

// LoadConfig reads and parses a keep config file, expanding environment variables.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	data = shared.ExpandEnvVarsInYAML(data)
	var cfg Config
	return cfg, yaml.Unmarshal(data, &cfg)
}
