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

package config

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/paclabsnet/PortcullisMCP/internal/shared/tlsutil"
	"github.com/paclabsnet/PortcullisMCP/internal/telemetry"
)

const (
	// ModeProduction is the strict security mode (default).
	ModeProduction = "production"
	// ModeDev is the relaxed security mode for local development.
	ModeDev = "dev"
)

// SourceMap maps resolved config field paths to their secret resolution source.
// Fields absent from the map were not secret URIs and have source "static".
// Produced by secrets.ResolveConfig and passed into Config.Validate().
type SourceMap map[string]string

// IsLoopback returns true if the address (host or host:port) is local-only.
func IsLoopback(addr string) bool {
	host := addr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		host = addr[:idx]
	}
	switch host {
	case "localhost", "127.0.0.1", "::1", "":
		return true
	}
	return false
}

// PeerAuth defines how one Portcullis service connects and authenticates to another.
type PeerAuth struct {
	Endpoint string       `yaml:"endpoint"` // e.g. "https://keep.internal.example.com"
	Auth     AuthSettings `yaml:"auth"`
}

// GuardPeerConfig holds connection settings for services connecting to Portcullis-Guard.
type GuardPeerConfig struct {
	PeerAuth  `yaml:",inline"`
	Endpoints GuardEndpoints `yaml:"endpoints"`
}

// NormalizationPeerConfig holds settings for the identity normalization webhook peer.
type NormalizationPeerConfig struct {
	PeerAuth     `yaml:",inline"`
	AllowClaims  []string `yaml:"allow_claims"`  // if non-empty, only these claims are forwarded
	DenyClaims   []string `yaml:"deny_claims"`   // claims always excluded from the webhook payload
	Timeout      int      `yaml:"timeout"`       // seconds; default 10
	MaxPayloadKB int      `yaml:"max_payload_kb"` // max request/response body size; default 128
}

// GuardEndpoints holds URLs for human and machine interfaces of Guard.
type GuardEndpoints struct {
	ApprovalUI string `yaml:"approval_ui"`
	TokenAPI   string `yaml:"token_api"`
}

// AuthSettings defines the authentication method and credentials for a peer or endpoint.
type AuthSettings struct {
	Type        string          `yaml:"type"` // "none", "bearer", "mtls"
	Credentials AuthCredentials `yaml:"credentials"`
}

// AuthCredentials holds the secrets used for peer-to-peer authentication.
type AuthCredentials struct {
	BearerToken string `yaml:"bearer_token"`
	Cert        string `yaml:"cert"`
	Key         string `yaml:"key"`
	ServerCA    string `yaml:"server_ca"`
	Header      string `yaml:"header"` // header name for token extraction (e.g. "X-User-Token")
}

// ServerConfig defines the listening endpoints and their security settings.
type ServerConfig struct {
	Endpoints  map[string]EndpointConfig `yaml:"endpoints"`
	SessionTTL int                       `yaml:"session_ttl"` // seconds; required in multi-tenant mode
}

// EndpointConfig defines a single listening port and its auth requirements.
type EndpointConfig struct {
	Listen string            `yaml:"listen"`
	TLS    tlsutil.TLSConfig `yaml:"tls"`
	Auth   AuthSettings      `yaml:"auth"`
	// ForwardHeaders specifies which HTTP request headers are forwarded from the
	// client into the Portcullis pipeline via EnrichedMCPRequest.ClientHeaders.
	// Supports exact names, prefix wildcards (x-tenant-*), or "*" for all
	// non-forbidden headers. Default: ["*"] (forward everything allowed).
	ForwardHeaders []string `yaml:"forward_headers"`
}

// IsSecure returns true if TLS is configured with a cert and key.
func (e EndpointConfig) IsSecure() bool {
	return e.TLS.Cert != "" && e.TLS.Key != ""
}

// IdentityConfig defines the source of user identity for the component.
type IdentityConfig struct {
	Strategy string                 `yaml:"strategy"`
	Config   map[string]interface{} `yaml:"config"`
}

// OIDCBaseConfig defines the fundamental settings for an OIDC provider.
// Embed this in a component-specific identity config struct to share common fields.
type OIDCBaseConfig struct {
	IssuerURL string `yaml:"issuer_url" mapstructure:"issuer_url"`
	Client    struct {
		ID     string `yaml:"id" mapstructure:"id"`
		Secret string `yaml:"secret" mapstructure:"secret"`
	} `yaml:"client" mapstructure:"client"`
	Scopes      []string `yaml:"scopes" mapstructure:"scopes"`
	RedirectURI string   `yaml:"redirect_uri" mapstructure:"redirect_uri"`
}

// OperationsConfig holds the "run-the-service" settings like logging and telemetry.
type OperationsConfig struct {
	Storage   StorageConfig    `yaml:"storage"`
	Telemetry telemetry.Config `yaml:"telemetry"`
	Logging   LoggingConfig    `yaml:"logging"`
	Limits    map[string]any   `yaml:"limits"`
}

// StorageConfig defines the backend storage settings using the Strategy+Config pattern.
type StorageConfig struct {
	Backend string                 `yaml:"backend"`
	Config  map[string]interface{} `yaml:"config"`
}

// LoggingConfig defines structured logging settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// BootstrapLogger installs a minimal INFO-level text logger on stderr. Call
// this as the first line of main() so that messages emitted before the config
// file is loaded and SetupLogging is called go somewhere useful.
func BootstrapLogger() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
}

// resolveLogLevel determines the effective log level string and whether a
// production-mode override notice must be emitted.
// Precedence (highest to lowest): levelOverride > cfg.Level > "info".
// In production mode, levelOverride is suppressed and emitNotice is set true.
func resolveLogLevel(cfg LoggingConfig, mode, levelOverride string) (level string, emitNotice bool) {
	if mode == ModeProduction && levelOverride != "" {
		emitNotice = true
		levelOverride = ""
	}
	switch {
	case levelOverride != "":
		level = levelOverride
	case cfg.Level != "":
		level = cfg.Level
	default:
		level = "info"
	}
	return level, emitNotice
}

// parseLevel converts a level string to slog.Level. Matching is case-insensitive.
// An empty string resolves to INFO. Returns an error for unrecognised values.
func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid log level %q: must be debug, info, warn, or error", s)
	}
}

// SetupLogging configures the global slog logger. Call this after LoadConfig
// and before component initialisation (including telemetry). In production mode,
// levelOverride is ignored and a notice is logged explaining why. The effective
// level is included in that notice.
// Returns an error if any level string is invalid so the caller can exit cleanly.
func SetupLogging(cfg LoggingConfig, mode, levelOverride string) error {
	return setupLogging(cfg, mode, levelOverride, os.Stderr)
}

// setupLogging is the testable core of SetupLogging; w receives all log output.
func setupLogging(cfg LoggingConfig, mode, levelOverride string, w io.Writer) error {
	effectiveLevel, emitNotice := resolveLogLevel(cfg, mode, levelOverride)

	level, err := parseLevel(effectiveLevel)
	if err != nil {
		return err
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.ToLower(cfg.Format) == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}
	slog.SetDefault(slog.New(handler))

	if emitNotice {
		slog.Warn("NOTICE: --log-level flag ignored in production mode",
			"reason", "command-line log level overrides are not permitted in production mode; update the configuration file to change log level",
			"effective_level", effectiveLevel)
	}

	return nil
}

// Activity log defaults. All are used by MCPActivityLogConfig.ApplyDefaults and
// referenced directly by any code that needs a safe zero-guard fallback.
const (
	DefaultMaxPayloadBytes     = 4096  // preview/truncation cap per record field
	DefaultMaxSizeMB           = 100   // rotate log file after this many MB
	DefaultMaxBackups          = 10    // number of rotated files to retain
	DefaultMaxAgeDays          = 30    // delete rotated files older than this
	DefaultBufferSize          = 10000 // async channel entries
	DefaultBatchSize           = 100   // remote sink batch size
	DefaultMaxQueuedBatches    = 10    // remote sink dispatcher queue depth
	DefaultFlushIntervalMS     = 1000  // remote sink partial-batch flush interval
	DefaultTimeoutMS           = 5000  // remote sink HTTP request timeout
	DefaultMaxRetries          = 0     // remote sink retry count on 5xx / network errors; 0 = no retries
	DefaultRetryBackoffMS      = 200   // remote sink inter-retry sleep
)

// HTTPActivityAuthConfig configures authentication for the HTTP and OTLP activity log sinks.
type HTTPActivityAuthConfig struct {
	// Type is the auth scheme: "splunk" (Splunk <token>), "bearer" (Bearer <token>), or "none".
	Type  string `yaml:"type"`
	// Token is the secret value. Supports envvar:// and vault:// URI schemes.
	Token string `yaml:"token"`
}

// ActivityTLSConfig configures custom TLS for remote activity log sinks.
type ActivityTLSConfig struct {
	// CACertFile is the path to a PEM-encoded CA certificate file on disk.
	CACertFile string `yaml:"ca_cert_file"`
	// CACertPEM is a PEM-encoded CA certificate string. Supports envvar:// and vault:// URIs.
	CACertPEM string `yaml:"ca_cert_pem"`
	// InsecureSkipVerify disables TLS server certificate verification. For development only.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// HTTPActivitySinkConfig configures the HTTPS batch activity log sink.
// Active when mcp_activity_log.sink is "http".
type HTTPActivitySinkConfig struct {
	// URL is the ingest endpoint (e.g. Splunk HEC raw endpoint or Logstash HTTP input).
	URL string `yaml:"url"`
	// Encoding is the batch wire format: "ndjson" (default) or "json_array".
	Encoding         string                 `yaml:"encoding"`
	Auth             HTTPActivityAuthConfig `yaml:"auth"`
	Headers          map[string]string      `yaml:"headers"`
	BatchSize        int                    `yaml:"batch_size"`
	MaxQueuedBatches int                    `yaml:"max_queued_batches"`
	FlushIntervalMS  int                    `yaml:"flush_interval_ms"`
	TimeoutMS        int                    `yaml:"timeout_ms"`
	MaxRetries       int                    `yaml:"max_retries"`
	RetryBackoffMS   int                    `yaml:"retry_backoff_ms"`
	TLS              ActivityTLSConfig      `yaml:"tls"`
}

// OTLPActivitySinkConfig configures the OpenTelemetry OTLP/HTTP activity log sink.
// Active when mcp_activity_log.sink is "otlp".
type OTLPActivitySinkConfig struct {
	// Endpoint is the OTLP/HTTP logs endpoint (e.g. https://otel-collector:4318/v1/logs).
	Endpoint         string                 `yaml:"endpoint"`
	Auth             HTTPActivityAuthConfig `yaml:"auth"`
	Headers          map[string]string      `yaml:"headers"`
	BatchSize        int                    `yaml:"batch_size"`
	MaxQueuedBatches int                    `yaml:"max_queued_batches"`
	FlushIntervalMS  int                    `yaml:"flush_interval_ms"`
	TimeoutMS        int                    `yaml:"timeout_ms"`
	MaxRetries       int                    `yaml:"max_retries"`
	RetryBackoffMS   int                    `yaml:"retry_backoff_ms"`
	TLS              ActivityTLSConfig      `yaml:"tls"`
}

// MCPActivityLogConfig defines the Keep MCP activity log settings.
// Set enabled: true to activate. All other fields have defaults applied by ApplyDefaults.
type MCPActivityLogConfig struct {
	Enabled bool `yaml:"enabled"`
	// Sink selects the output target: "file" (default), "stdout", "http", or "otlp".
	Sink string `yaml:"sink"`
	// File is the rotating log file path. Used when Sink is "file".
	// Default: "/var/log/portcullis/mcp-activity.log"
	File       string `yaml:"file"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAgeDays int    `yaml:"max_age_days"`
	// Compress controls gzip compression of rotated files. Default: false.
	Compress bool `yaml:"compress"`
	// IncludePDPDecision controls whether pdp_decision and pdp_reason appear in request records.
	// Default: false.
	IncludePDPDecision bool   `yaml:"include_pdp_decision"`
	TruncatePayloads   bool   `yaml:"truncate_payloads"`
	MaxPayloadBytes    int    `yaml:"max_payload_bytes"`
	BufferSize         int    `yaml:"buffer_size"`
	HTTP               HTTPActivitySinkConfig  `yaml:"http"`
	OTLP               OTLPActivitySinkConfig  `yaml:"otlp"`
}

// DefaultMCPActivityLogConfig returns an MCPActivityLogConfig with all defaults applied.
func DefaultMCPActivityLogConfig() MCPActivityLogConfig {
	c := MCPActivityLogConfig{}
	c.ApplyDefaults()
	return c
}

// ApplyDefaults fills zero-value fields with their service defaults.
func (c *MCPActivityLogConfig) ApplyDefaults() {
	if c.Sink == "" {
		// Back-compat: if File was set to "stdout", honour it via the new Sink field.
		if c.File == "stdout" {
			c.Sink = "stdout"
		} else {
			c.Sink = "file"
		}
	}
	if c.File == "" {
		c.File = "/var/log/portcullis/mcp-activity.log"
	}
	if c.MaxSizeMB == 0 {
		c.MaxSizeMB = DefaultMaxSizeMB
	}
	if c.MaxBackups == 0 {
		c.MaxBackups = DefaultMaxBackups
	}
	if c.MaxAgeDays == 0 {
		c.MaxAgeDays = DefaultMaxAgeDays
	}
	if c.MaxPayloadBytes == 0 {
		c.MaxPayloadBytes = DefaultMaxPayloadBytes
	}
	if c.BufferSize == 0 {
		c.BufferSize = DefaultBufferSize
	}
	// HTTP sink defaults
	if c.HTTP.Encoding == "" {
		c.HTTP.Encoding = "ndjson"
	}
	if c.HTTP.Auth.Type == "" {
		c.HTTP.Auth.Type = "none"
	}
	if c.HTTP.BatchSize == 0 {
		c.HTTP.BatchSize = DefaultBatchSize
	}
	if c.HTTP.MaxQueuedBatches == 0 {
		c.HTTP.MaxQueuedBatches = DefaultMaxQueuedBatches
	}
	if c.HTTP.FlushIntervalMS == 0 {
		c.HTTP.FlushIntervalMS = DefaultFlushIntervalMS
	}
	if c.HTTP.TimeoutMS == 0 {
		c.HTTP.TimeoutMS = DefaultTimeoutMS
	}
	if c.HTTP.RetryBackoffMS == 0 {
		c.HTTP.RetryBackoffMS = DefaultRetryBackoffMS
	}
	// OTLP sink defaults
	if c.OTLP.Auth.Type == "" {
		c.OTLP.Auth.Type = "none"
	}
	if c.OTLP.BatchSize == 0 {
		c.OTLP.BatchSize = DefaultBatchSize
	}
	if c.OTLP.MaxQueuedBatches == 0 {
		c.OTLP.MaxQueuedBatches = DefaultMaxQueuedBatches
	}
	if c.OTLP.FlushIntervalMS == 0 {
		c.OTLP.FlushIntervalMS = DefaultFlushIntervalMS
	}
	if c.OTLP.TimeoutMS == 0 {
		c.OTLP.TimeoutMS = DefaultTimeoutMS
	}
	if c.OTLP.RetryBackoffMS == 0 {
		c.OTLP.RetryBackoffMS = DefaultRetryBackoffMS
	}
}

// Validate returns an error if the configuration is inconsistent or invalid.
// ApplyDefaults must be called before Validate.
func (c *MCPActivityLogConfig) Validate() error {
	switch c.Sink {
	case "file", "stdout", "http", "otlp":
		// valid
	default:
		return fmt.Errorf("unknown sink type %q: must be \"file\", \"stdout\", \"http\", or \"otlp\"", c.Sink)
	}
	if c.Sink == "http" {
		if err := validateHTTPSinkConfig(&c.HTTP); err != nil {
			return fmt.Errorf("http sink: %w", err)
		}
	}
	if c.Sink == "otlp" {
		if err := validateOTLPSinkConfig(&c.OTLP); err != nil {
			return fmt.Errorf("otlp sink: %w", err)
		}
	}
	return nil
}

func validateHTTPSinkConfig(cfg *HTTPActivitySinkConfig) error {
	if cfg.URL == "" {
		return fmt.Errorf("http url is required")
	}
	switch cfg.Encoding {
	case "ndjson", "json_array":
		// valid
	default:
		return fmt.Errorf("invalid encoding %q: must be \"ndjson\" or \"json_array\"", cfg.Encoding)
	}
	if err := validateActivityAuthConfig(&cfg.Auth); err != nil {
		return err
	}
	return validateNetworkSinkTuning(cfg.BatchSize, cfg.MaxQueuedBatches, cfg.FlushIntervalMS, cfg.TimeoutMS, cfg.MaxRetries, cfg.RetryBackoffMS)
}

func validateOTLPSinkConfig(cfg *OTLPActivitySinkConfig) error {
	if cfg.Endpoint == "" {
		return fmt.Errorf("otlp endpoint is required")
	}
	if err := validateActivityAuthConfig(&cfg.Auth); err != nil {
		return err
	}
	return validateNetworkSinkTuning(cfg.BatchSize, cfg.MaxQueuedBatches, cfg.FlushIntervalMS, cfg.TimeoutMS, cfg.MaxRetries, cfg.RetryBackoffMS)
}

// validateNetworkSinkTuning checks the shared numeric tuning fields used by
// both the HTTP and OTLP sinks. Values that would cause a panic at construction
// time (non-positive channel capacity or ticker interval) are rejected.
func validateNetworkSinkTuning(batchSize, maxQueuedBatches, flushIntervalMS, timeoutMS, maxRetries, retryBackoffMS int) error {
	if batchSize <= 0 {
		return fmt.Errorf("batch_size must be > 0")
	}
	if maxQueuedBatches <= 0 {
		return fmt.Errorf("max_queued_batches must be > 0")
	}
	if flushIntervalMS <= 0 {
		return fmt.Errorf("flush_interval_ms must be > 0")
	}
	if timeoutMS <= 0 {
		return fmt.Errorf("timeout_ms must be > 0")
	}
	if maxRetries < 0 {
		return fmt.Errorf("max_retries must be >= 0")
	}
	if retryBackoffMS < 0 {
		return fmt.Errorf("retry_backoff_ms must be >= 0")
	}
	return nil
}

func validateActivityAuthConfig(cfg *HTTPActivityAuthConfig) error {
	switch cfg.Type {
	case "none", "":
		// valid
	case "splunk", "bearer":
		if cfg.Token == "" {
			return fmt.Errorf("auth token required when auth type is %q", cfg.Type)
		}
	default:
		return fmt.Errorf("unsupported auth type %q: must be \"none\", \"splunk\", or \"bearer\"", cfg.Type)
	}
	return nil
}
