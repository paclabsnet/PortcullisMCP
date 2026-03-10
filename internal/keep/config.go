package keep

// Config holds the full portcullis-keep configuration loaded from keep.yaml.
type Config struct {
	Listen      ListenConfig             `yaml:"listen"`
	PDP         PDPConfig                `yaml:"pdp"`
	Backends    map[string]BackendConfig `yaml:"backends"`
	Escalation  EscalationConfig         `yaml:"escalation"`
	DecisionLog DecisionLogConfig        `yaml:"decision_log"`
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
}

type EscalationConfig struct {
	Workflow WorkflowConfig `yaml:"workflow"`
}

type WorkflowConfig struct {
	Type       string           `yaml:"type"` // "servicenow" | "webhook"
	ServiceNow ServiceNowConfig `yaml:"servicenow"`
	Webhook    WebhookConfig    `yaml:"webhook"`
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
