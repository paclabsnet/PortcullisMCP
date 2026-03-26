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
	"keep.auth.key",
	"guard.bearer_token",
	"management_api.shared_secret",
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
	Source      string     `yaml:"source"` // "oidc" | "os"
	OIDC        OIDCConfig `yaml:"oidc"`
	UserID      string     `yaml:"user_id"`      // optional: override user ID when source is "os" (for testing)
	DisplayName string     `yaml:"display_name"` // optional: override display name when source is "os" (for testing)
	Groups      []string   `yaml:"groups"`       // optional: groups to assign when source is "os" (for testing)
}

// Validate returns an error if the identity config contains invalid values.
func (c IdentityConfig) Validate() error {
	switch c.Source {
	case "", "os":
		// valid
	case "oidc":
		if c.OIDC.TokenFile == "" {
			return fmt.Errorf("identity.oidc.token_file is required when identity.source is \"oidc\"")
		}
	default:
		return fmt.Errorf("invalid identity.source %q: must be \"oidc\" or \"os\"", c.Source)
	}
	return nil
}

type OIDCConfig struct {
	TokenFile string `yaml:"token_file"`
}

type SandboxConfig struct {
	Directory string `yaml:"directory"`
}

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
	Endpoint                   string `yaml:"endpoint"`                     // e.g. "https://guard.internal.example.com"
	BearerToken                string `yaml:"bearer_token"`                 // for /token/unclaimed/list, /token/deposit, and /pending
	PollInterval               int    `yaml:"poll_interval"`                // seconds between polls of /token/unclaimed/list (default: 60)
	ApprovalManagementStrategy string `yaml:"approval_management_strategy"` // "proactive" | "user-driven" (default: "user-driven")
}

// Validate returns an error if the guard connection config contains invalid values.
func (c GuardConfig) Validate() error {
	switch c.ApprovalManagementStrategy {
	case "", "user-driven", "proactive":
		// valid
	default:
		return fmt.Errorf("invalid approval_management_strategy %q: must be \"user-driven\" or \"proactive\"", c.ApprovalManagementStrategy)
	}
	if c.ApprovalManagementStrategy == "proactive" && c.Endpoint == "" {
		return fmt.Errorf("guard.endpoint is required when approval_management_strategy is \"proactive\"")
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
	Approval AgentApprovalConfig `yaml:"approval"`
}

// AgentApprovalConfig controls the message Gate returns to the agent when
// escalation is required. Supports {reason} and {url} template placeholders.
type AgentApprovalConfig struct {
	// Instructions overrides the default escalation message shown to the agent.
	// If empty, a built-in default is used.
	Instructions string `yaml:"instructions"`
}
