package gate

// Config holds the full portcullis-gate configuration loaded from gate.yaml.
type Config struct {
	Keep           KeepConfig       `yaml:"keep"`
	Identity       IdentityConfig   `yaml:"identity"`
	Sandbox        SandboxConfig    `yaml:"sandbox"`
	ProtectedPaths []string         `yaml:"protected_paths"`
	ManagementAPI  MgmtAPIConfig    `yaml:"management_api"`
	TokenStore     string           `yaml:"token_store"`
	LogBatching    LogBatchingConfig `yaml:"log_batching"`
}

type KeepConfig struct {
	Endpoint string     `yaml:"endpoint"`
	Auth     KeepAuth   `yaml:"auth"`
}

type KeepAuth struct {
	Type string `yaml:"type"` // "mtls" | "bearer"
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	Token string `yaml:"token"`
}

type IdentityConfig struct {
	Source string     `yaml:"source"` // "oidc" | "os"
	OIDC   OIDCConfig `yaml:"oidc"`
}

type OIDCConfig struct {
	TokenFile string `yaml:"token_file"`
}

type SandboxConfig struct {
	Directory string `yaml:"directory"`
}

type MgmtAPIConfig struct {
	Port         int    `yaml:"port"`
	SharedSecret string `yaml:"shared_secret"` // optional; empty = no auth
}

type LogBatchingConfig struct {
	FlushIntervalSeconds int `yaml:"flush_interval_seconds"` // seconds between flushes (default: 30)
	MaxBatchSize         int `yaml:"max_batch_size"`         // max entries per batch (default: 100)
}
