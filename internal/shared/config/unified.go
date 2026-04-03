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
}

// ServerConfig defines the listening endpoints and their security settings.
type ServerConfig struct {
	Endpoints map[string]EndpointConfig `yaml:"endpoints"`
}

// EndpointConfig defines a single listening port and its auth requirements.
type EndpointConfig struct {
	Listen string            `yaml:"listen"`
	TLS    tlsutil.TLSConfig `yaml:"tls"`
	Auth   AuthSettings      `yaml:"auth"`
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

// DecisionLogConfig defines how policy decisions are recorded and dispatched.
type DecisionLogConfig struct {
	Enabled       bool              `yaml:"enabled"`
	BufferSize    int               `yaml:"buffer_size"`
	FlushInterval int               `yaml:"flush_interval"`
	MaxBatchSize  int               `yaml:"max_batch_size"`
	URL           string            `yaml:"url"`
	Headers       map[string]string `yaml:"headers"`
	Console       bool              `yaml:"console"`
}
