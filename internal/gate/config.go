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

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
	telemetrycfg "github.com/paclabsnet/PortcullisMCP/internal/telemetry"
)

// SecretAllowlist lists the config fields eligible for vault:// and other
// restricted secret URI schemes. envvar:// and filevar:// may be used on any field.
var SecretAllowlist = []string{
	"keep.auth.token",
	"keep.auth.cert",
	"keep.auth.key",
	"keep.auth.server_ca",
	"guard.bearer_token",
	"management_api.shared_secret",
	"identity.oidc_login.client_secret",
}

// LoadConfig reads, parses, resolves secrets in, and validates a gate config file.
// It uses strict unmarshaling to ensure that unknown or deprecated fields
// cause a configuration error at startup. ~ in path is expanded to the
// user home directory.
func LoadConfig(ctx context.Context, path string) (Config, error) {
	return cfgloader.Load[Config](ctx, path, SecretAllowlist)
}

// Config holds the full portcullis-gate configuration loaded from gate.yaml.
type Config struct {
	Keep           KeepConfig             `yaml:"keep"`
	Guard          GuardConfig            `yaml:"guard"`
	Identity       IdentityConfig         `yaml:"identity"`
	Sandbox        SandboxConfig          `yaml:"sandbox"`
	ProtectedPaths []string               `yaml:"protected_paths"`
	ManagementAPI  MgmtAPIConfig          `yaml:"management_api"`
	TokenStore     string                 `yaml:"token_store"`
	DecisionLogs   DecisionLogBatchConfig `yaml:"decision_logs"`
	Telemetry      telemetrycfg.Config    `yaml:"telemetry"`
	Agent          AgentConfig            `yaml:"agent"`
}

type KeepConfig struct {
	Endpoint string   `yaml:"endpoint"`
	Auth     KeepAuth `yaml:"auth"`
}

type KeepAuth struct {
	Type     string `yaml:"type"`      // "mtls" | "bearer"
	Cert     string `yaml:"cert"`      // client certificate for mTLS
	Key      string `yaml:"key"`       // client key for mTLS
	Token    string `yaml:"token"`     // bearer token
	ServerCA string `yaml:"server_ca"` // CA cert for verifying Keep's TLS certificate (enterprise/private CA)
}

type IdentityConfig struct {
	Source                   string          `yaml:"source"` // "oidc-file" | "oidc-login" | "os"
	OIDCFile                 OIDCFileConfig  `yaml:"oidc_file"`
	OIDCLogin                OIDCLoginConfig `yaml:"oidc_login"`
	LoginCallbackTimeoutSecs int    `yaml:"login_callback_timeout_seconds"` // seconds user has to complete login after StartLogin; default 600
	LoginCallbackPageFile    string `yaml:"login_callback_page_file"`       // default: embedded
	UserID                string   `yaml:"user_id"`                  // optional: override user ID when source is "os" (for testing)
	DisplayName              string          `yaml:"display_name"`                   // optional: override display name when source is "os" (for testing)
	Groups                   []string        `yaml:"groups"`                         // optional: groups to assign when source is "os" (for testing)
}

// Validate returns an error if the identity config contains invalid values.
func (c IdentityConfig) Validate() error {
	switch c.Source {
	case "", "os":
		// valid
	case "oidc-file":
		if c.OIDCFile.TokenFile == "" {
			return fmt.Errorf("identity.oidc_file.token_file is required when identity.source is \"oidc-file\"")
		}
	case "oidc-login":
		if c.OIDCLogin.IssuerURL == "" {
			return fmt.Errorf("identity.oidc_login.issuer_url is required when identity.source is \"oidc-login\"")
		}
		if c.OIDCLogin.ClientID == "" {
			return fmt.Errorf("identity.oidc_login.client_id is required when identity.source is \"oidc-login\"")
		}
		if c.OIDCLogin.Flow != "" && c.OIDCLogin.Flow != "authorization_code" {
			return fmt.Errorf("identity.oidc_login.flow %q is not supported; only \"authorization_code\" is valid", c.OIDCLogin.Flow)
		}
	default:
		return fmt.Errorf("invalid identity.source %q: must be \"oidc-file\", \"oidc-login\", or \"os\"", c.Source)
	}
	return nil
}

// OIDCFileConfig holds settings for the oidc-file identity source.
type OIDCFileConfig struct {
	TokenFile string `yaml:"token_file"`
}

// OIDCLoginConfig holds settings for the oidc-login interactive login flow.
type OIDCLoginConfig struct {
	IssuerURL    string   `yaml:"issuer_url"`
	RedirectURI  string   `yaml:"redirect_uri"`  // if blank: http://localhost:{mgmt_port}/auth/callback
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"` // supports envvar:// etc
	Scopes       []string `yaml:"scopes"`
	Flow         string   `yaml:"flow"` // must be "authorization_code"
}

type SandboxConfig struct {
	Directory   string   `yaml:"directory"`   // backward-compatible single-entry alias
	Directories []string `yaml:"directories"` // multi-directory list
}

// EffectiveDirs returns the deduplicated list of configured sandbox directories.
// Directory is included as the first entry when set and not already present in
// Directories. Paths are returned as-is; callers are responsible for ~ expansion.
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

// DefaultManagementAPIPort is the port used for the Gate management API when
// management_api.port is not set in the config.
const DefaultManagementAPIPort = 7777

type MgmtAPIConfig struct {
	Port              int    `yaml:"port"`
	SharedSecret      string `yaml:"shared_secret"`       // optional; empty = no auth
	AllowManualTokens bool   `yaml:"allow_manual_tokens"` // default false; set true to allow POST /tokens from the UI
}

type DecisionLogBatchConfig struct {
	FlushInterval int `yaml:"flush_interval"` // seconds between flushes (default: 30)
	MaxBatchSize  int `yaml:"max_batch_size"` // max entries per batch (default: 100)
}

// GuardConfig holds connection settings for the portcullis-guard token claim API.
// Guard is required to be able to create escalation tokens that can be trusted by
// the PDP, which is the core of the system. Having said that, a Portcullis system
// without a Guard can still handle accept / deny (and possibly workflow) responses
// from the PDP. In essence, Guard is what gives a human the ability to escalate the
// Agents' authorization privileges for a short time
//
// to make this explicit: if you do not have a Portcullis-Guard configuration, we
// do not offer escalation as an option for the Agent. Without access to Guard, an escalation
// response from Portcullis-Keep will be treated as a deny.
//
// using the metaphor of an actual castle:
//
// An agent for a nearby lord walks up to the Gate of Castle Evermoor and seeks to enter to deliver
// a message to Viscount Evermoor .  But it is late, and the policy is not to let anyone in after
// dark unless the matter is urgent.  So the agent goes back to his lord, and acquires a signed
// affadivit indicating that this request is, in fact urgent.
//   - if there is a Guard at the Gate, the Guard can let the user into the Keep so he can visit the Lord
//     and deliver the message
//   - if there is no Guard on duty, it doesn't matter that the agent has a signed affadavit - the Portcullis
//     is closed, and the agent is denied.
//
// Note: technically, a very knowledgeable user with access to the necessary secrets
// can still make escalation work manually, but it requires creating a JWT by hand using
// deep knowledge of the Rego structures and policies, and the capabilities
// of PortcullisGate's web interface
type GuardConfig struct {
	// EscalationApprovalEndpoint is the human-facing base URL of portcullis-guard,
	// used to construct the /approve link shown to the user and their agent.
	// In production this should be the SSO-proxy-protected address
	// (e.g. "https://guard.corp.example.com") so that agents cannot self-approve
	// escalations by fetching the URL programmatically.
	// See docs/guard-sso-proxy.md for deployment guidance.
	EscalationApprovalEndpoint string `yaml:"escalation_approval_endpoint"`

	// TokenAPIEndpoint is the machine-to-machine base URL used by Gate for
	// /token/unclaimed/list, /token/claim, and /pending API calls (bearer-token
	// protected). Set this to the internal Guard address when the SSO proxy is on
	// a separate hostname from the API. Defaults to EscalationApprovalEndpoint
	// when unset, which is correct for single-hostname deployments.
	TokenAPIEndpoint string `yaml:"token_api_endpoint"`

	BearerToken                string `yaml:"bearer_token"`                 // for /token/unclaimed/list, /token/deposit, and /pending
	PollInterval               int    `yaml:"poll_interval"`                // seconds between polls of /token/unclaimed/list (default: 60)
	ApprovalManagementStrategy string `yaml:"approval_management_strategy"` // "proactive" | "user-driven" (default: "user-driven")
}

// resolvedAPIEndpoint returns the endpoint Gate should use for machine-to-machine
// Guard API calls. It returns TokenAPIEndpoint if set, and falls back to
// EscalationApprovalEndpoint for single-hostname deployments.
func (c GuardConfig) resolvedAPIEndpoint() string {
	if c.TokenAPIEndpoint != "" {
		return c.TokenAPIEndpoint
	}
	return c.EscalationApprovalEndpoint
}

// Validate returns an error if the guard connection config contains invalid values.
func (c GuardConfig) Validate() error {
	switch c.ApprovalManagementStrategy {
	case "", "user-driven", "proactive":
		// valid
	default:
		return fmt.Errorf("invalid approval_management_strategy %q: must be \"user-driven\" or \"proactive\"", c.ApprovalManagementStrategy)
	}
	if c.ApprovalManagementStrategy == "proactive" && c.EscalationApprovalEndpoint == "" {
		return fmt.Errorf("guard.escalation_approval_endpoint is required when approval_management_strategy is \"proactive\"")
	}
	return nil
}

// Validate returns an error if the configuration contains invalid values.
func (c Config) Validate() error {
	if c.Keep.Endpoint == "" {
		return fmt.Errorf("keep.endpoint is required")
	}
	if err := c.Identity.Validate(); err != nil {
		return err
	}
	return c.Guard.Validate()
}

// AgentConfig holds settings that control how Gate communicates with the MCP agent.
type AgentConfig struct {
	RequireApproval AgentRequireApprovalConfig `yaml:"require_approval"`
	Deny            AgentDenyConfig            `yaml:"deny"`
}

// AgentRequireApprovalConfig controls the message Gate returns to the agent when
// escalation or workflow approval is required. Supports {reason}, {url}, and
// {trace_id} template placeholders. If empty, a built-in default is used.
type AgentRequireApprovalConfig struct {
	Instructions string `yaml:"instructions"`
}

// AgentDenyConfig controls the message Gate returns to the agent when a
// request is denied by policy. Supports {reason} and {trace_id} template
// placeholders. Omit either placeholder to hide that information from the
// agent. If empty, a built-in default (including both) is used.
type AgentDenyConfig struct {
	Instructions string `yaml:"instructions"`
}
