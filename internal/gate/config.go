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

package gate

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// SecretAllowlist lists the config fields eligible for vault:// and other
// restricted secret URI schemes. envvar:// and filevar:// may be used on any field.
var SecretAllowlist = []string{
	"peers.keep.auth.credentials.bearer_token",
	"peers.keep.auth.credentials.cert",
	"peers.keep.auth.credentials.key",
	"peers.keep.auth.credentials.server_ca",
	"peers.guard.auth.credentials.bearer_token",
	"server.endpoints.management_ui.auth.credentials.bearer_token",
	"server.endpoints.mcp.auth.credentials.bearer_token",
	"identity.config.client_secret",
}

// LoadConfig reads, parses, resolves secrets in, and validates a gate config file.
// It returns the config and a PostureReport for startup security attestation.
func LoadConfig(ctx context.Context, path string) (Config, cfgloader.PostureReport, error) {
	cfg, report, err := cfgloader.Load[*Config](ctx, path, SecretAllowlist)
	if err != nil {
		return Config{}, report, err
	}
	return *cfg, report, nil
}

// Config holds the full portcullis-gate configuration loaded from gate.yaml.
type Config struct {
	Tenancy        string                     `yaml:"tenancy"` // "single" (default) or "multi"
	Mode           string                     `yaml:"mode"`
	Server         cfgloader.ServerConfig     `yaml:"server"`
	Identity       IdentityConfig             `yaml:"identity"`
	Peers          PeersConfig                `yaml:"peers"`
	Responsibility ResponsibilityConfig       `yaml:"responsibility"`
	Operations     cfgloader.OperationsConfig `yaml:"operations"`

	// Deprecated / Backwards compatibility for internal usage only
	Agent AgentConfig `yaml:"agent"`
}

// Validate returns a PostureReport and an error if the configuration contains invalid values.
func (c *Config) Validate(sources cfgloader.SourceMap) (cfgloader.PostureReport, error) {
	if c.Mode == "" {
		c.Mode = cfgloader.ModeProduction
	}

	if c.Mode == cfgloader.ModeProduction {
		if c.Identity.Strategy == "os" {
			return cfgloader.PostureReport{}, fmt.Errorf("identity.strategy \"os\" is not allowed in production mode")
		}
		for name, ep := range c.Server.Endpoints {
			if ep.Auth.Type == "none" {
				return cfgloader.PostureReport{}, fmt.Errorf("auth.type \"none\" for endpoint %q is not allowed in production mode", name)
			}
			if !cfgloader.IsLoopback(ep.Listen) && !ep.IsSecure() {
				return cfgloader.PostureReport{}, fmt.Errorf("TLS is required for non-loopback endpoint %q in production mode", name)
			}
		}
	}

	if c.Peers.Keep.Endpoint == "" {
		return cfgloader.PostureReport{}, fmt.Errorf("peers.keep.endpoint is required")
	}
	if err := c.Identity.Validate(); err != nil {
		return cfgloader.PostureReport{}, err
	}
	if err := c.Peers.Guard.Validate(); err != nil {
		return cfgloader.PostureReport{}, err
	}

	switch c.Responsibility.Escalation.Strategy {
	case "", "user-driven", "proactive":
	default:
		return cfgloader.PostureReport{}, fmt.Errorf("invalid responsibility.escalation.strategy %q: must be \"user-driven\" or \"proactive\"", c.Responsibility.Escalation.Strategy)
	}
	if c.Responsibility.Escalation.Strategy == "proactive" && c.Peers.Guard.Endpoints.ApprovalUI == "" {
		return cfgloader.PostureReport{}, fmt.Errorf("peers.guard.endpoints.approval_ui is required when escalation strategy is \"proactive\"")
	}

	report := cfgloader.BuildPostureReport(c, sources, SecretAllowlist)

	if c.Mode != cfgloader.ModeProduction {
		report.SetStatus("mode", "WARN", "Use production mode for deployments")
	}
	if c.Identity.Strategy == "os" {
		report.SetStatus("identity.strategy", "WARN", "OS identity is not suitable for production; use oidc-file or oidc-login")
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

type PeersConfig struct {
	Keep  cfgloader.PeerAuth      `yaml:"keep"`
	Guard GateSpecificGuardConfig `yaml:"guard"`
}

// GateSpecificGuardConfig holds connection settings for Portcullis-Guard.
// Behavioral settings (strategy, poll_interval) are in Responsibility.Escalation.
type GateSpecificGuardConfig struct {
	cfgloader.GuardPeerConfig `yaml:",inline"`
}

// resolvedAPIEndpoint returns the endpoint Gate should use for machine-to-machine
// Guard API calls.
func (c GateSpecificGuardConfig) resolvedAPIEndpoint() string {
	if c.Endpoints.TokenAPI != "" {
		return c.Endpoints.TokenAPI
	}
	return c.Endpoints.ApprovalUI
}

// Validate returns an error if the guard connection config contains invalid values.
func (c GateSpecificGuardConfig) Validate() error {
	return nil
}

type IdentityConfig struct {
	Strategy                 string         `yaml:"strategy"` // "oidc-file" | "oidc-login" | "os"
	Config                   map[string]any `yaml:"config"`
	LoginCallbackTimeoutSecs int            `yaml:"login_callback_timeout_seconds"` // seconds user has to complete login after StartLogin; default 600
	LoginCallbackPageFile    string         `yaml:"login_callback_page_file"`       // default: embedded

	// Derived fields populated from Config map during Validate()
	OIDCFile  OIDCFileConfig  `yaml:"-"`
	OIDCLogin OIDCLoginConfig `yaml:"-"`
	OS        OSConfig        `yaml:"-"`
}

// Validate returns an error if the identity config contains invalid values.
func (c *IdentityConfig) Validate() error {
	if c.Config != nil {
		switch c.Strategy {
		case "oidc-file":
			if err := mapstructure.Decode(c.Config, &c.OIDCFile); err != nil {
				return fmt.Errorf("decode identity.config for oidc-file: %w", err)
			}
		case "oidc-login":
			if err := mapstructure.Decode(c.Config, &c.OIDCLogin); err != nil {
				return fmt.Errorf("decode identity.config for oidc-login: %w", err)
			}
		case "os":
			if err := mapstructure.Decode(c.Config, &c.OS); err != nil {
				return fmt.Errorf("decode identity.config for os: %w", err)
			}
		}
	}

	switch c.Strategy {
	case "", "os":
		// valid
	case "oidc-file":
		if c.OIDCFile.TokenFile == "" {
			return fmt.Errorf("identity.config.token_file is required when identity.strategy is \"oidc-file\"")
		}
	case "oidc-login":
		if c.OIDCLogin.IssuerURL == "" {
			return fmt.Errorf("identity.config.issuer_url is required when identity.strategy is \"oidc-login\"")
		}
		if c.OIDCLogin.ClientID == "" {
			return fmt.Errorf("identity.config.client_id is required when identity.strategy is \"oidc-login\"")
		}
		if c.OIDCLogin.Flow != "" && c.OIDCLogin.Flow != "authorization_code" {
			return fmt.Errorf("identity.config.flow %q is not supported; only \"authorization_code\" is valid", c.OIDCLogin.Flow)
		}
	default:
		return fmt.Errorf("invalid identity.strategy %q: must be \"oidc-file\", \"oidc-login\", or \"os\"", c.Strategy)
	}
	return nil
}

// OIDCFileConfig holds settings for the oidc-file identity source.
type OIDCFileConfig struct {
	TokenFile string `yaml:"token_file" mapstructure:"token_file"`
}

// OIDCLoginConfig holds settings for the oidc-login interactive login flow.
type OIDCLoginConfig struct {
	IssuerURL    string   `yaml:"issuer_url" mapstructure:"issuer_url"`
	RedirectURI  string   `yaml:"redirect_uri" mapstructure:"redirect_uri"`
	ClientID     string   `yaml:"client_id" mapstructure:"client_id"`
	ClientSecret string   `yaml:"client_secret" mapstructure:"client_secret"`
	Scopes       []string `yaml:"scopes" mapstructure:"scopes"`
	Flow         string   `yaml:"flow" mapstructure:"flow"`
}

// OSConfig holds overrides for the OS identity source.
type OSConfig struct {
	UserID      string   `yaml:"user_id" mapstructure:"user_id"`
	DisplayName string   `yaml:"display_name" mapstructure:"display_name"`
	Groups      []string `yaml:"groups" mapstructure:"groups"`
}

type ResponsibilityConfig struct {
	Tools            ToolsConfig            `yaml:"tools"`
	AgentInteraction AgentInteractionConfig `yaml:"agent_interaction"`
	Escalation       EscalationConfig       `yaml:"escalation"`
	DecisionLogs     DecisionLogBatchConfig `yaml:"decision_logs"`
}

// ToolsConfig groups all tool-provider configurations.
type ToolsConfig struct {
	LocalFS LocalFSConfig `yaml:"portcullis-localfs"`
}

// LocalFSConfig configures the built-in local filesystem tool provider.
type LocalFSConfig struct {
	Enabled   bool            `yaml:"enabled"`
	Workspace SandboxConfig   `yaml:"workspace"`
	Forbidden ForbiddenConfig `yaml:"forbidden"`
}

type EscalationConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Strategy           string `yaml:"strategy"`             // "proactive" | "user-driven" (default: "user-driven")
	PollInterval       int    `yaml:"poll_interval"`        // seconds between polls (default: 60)
	TokenStore         string `yaml:"token_store"`
	NoEscalationMarker string `yaml:"no_escalation_marker"` // marker returned instead of escalation in multi-tenant mode
}

type ForbiddenConfig struct {
	Directories []string `yaml:"directories"`
}

type AgentInteractionConfig struct {
	Instructions      AgentInstructionsConfig `yaml:"instructions"`
	AllowManualTokens bool                    `yaml:"allow_manual_tokens"`
}

type AgentInstructionsConfig struct {
	RequireApproval string `yaml:"require_approval"`
	Deny            string `yaml:"deny"`
}

type SandboxConfig struct {
	Directory   string   `yaml:"directory"`   // backward-compatible single-entry alias
	Directories []string `yaml:"directories"` // multi-directory list
}

// EffectiveDirs returns the deduplicated list of configured sandbox directories.
func (c SandboxConfig) EffectiveDirs() []string {
	seen := make(map[string]bool)
	var out []string
	add := func(d string) {
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	add(c.Directory)
	for _, d := range c.Directories {
		add(d)
	}
	return out
}

type DecisionLogBatchConfig struct {
	FlushInterval int `yaml:"flush_interval"` // seconds between flushes (default: 30)
	MaxBatchSize  int `yaml:"max_batch_size"` // max entries per batch (default: 100)
}

// DefaultManagementAPIPort is the port used for the Gate management API when
// responsibility.agent_interaction.port is not set.
const DefaultManagementAPIPort = 7777

// ManagementUIEndpoint is the key in the server.endpoints map for the Gate
// management interface.
const ManagementUIEndpoint = "management_ui"

// GuardConfig is an alias for GateSpecificGuardConfig for backward compatibility.
type GuardConfig = GateSpecificGuardConfig

// Deprecated / Backwards compatibility types
type AgentConfig struct {
	RequireApproval AgentRequireApprovalConfig `yaml:"require_approval"`
	Deny            AgentDenyConfig            `yaml:"deny"`
}

type AgentRequireApprovalConfig struct {
	Instructions string `yaml:"instructions"`
}

type AgentDenyConfig struct {
	Instructions string `yaml:"instructions"`
}
