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

import telemetrycfg "github.com/paclabsnet/PortcullisMCP/internal/telemetry"

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
}

type KeepConfig struct {
	Endpoint string     `yaml:"endpoint"`
	Auth     KeepAuth   `yaml:"auth"`
}

type KeepAuth struct {
	Type     string `yaml:"type"`      // "mtls" | "bearer"
	Cert     string `yaml:"cert"`      // client certificate for mTLS
	Key      string `yaml:"key"`       // client key for mTLS
	Token    string `yaml:"token"`     // bearer token
	ServerCA string `yaml:"server_ca"` // CA cert for verifying Keep's TLS certificate (enterprise/private CA)
}

type IdentityConfig struct {
	Source      string     `yaml:"source"`       // "oidc" | "os"
	OIDC        OIDCConfig `yaml:"oidc"`
	UserID      string     `yaml:"user_id"`      // optional: override user ID when source is "os" (for testing)
	DisplayName string     `yaml:"display_name"` // optional: override display name when source is "os" (for testing)
	Groups      []string   `yaml:"groups"`       // optional: groups to assign when source is "os" (for testing)
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

type DecisionLogBatchConfig struct {
	FlushInterval int `yaml:"flush_interval"` // seconds between flushes (default: 30)
	MaxBatchSize  int `yaml:"max_batch_size"` // max entries per batch (default: 100)
}

// GuardConfig holds connection settings for the portcullis-guard token claim API.
// If Endpoint is empty, the automatic token-claim flow is disabled and users must
// add escalation tokens manually via the management API.
type GuardConfig struct {
	Endpoint     string `yaml:"endpoint"`      // e.g. "https://guard.internal.example.com"
	BearerToken  string `yaml:"bearer_token"`  // for /token/unclaimed/list and /token/deposit
	PollInterval int    `yaml:"poll_interval"` // seconds between polls of /token/unclaimed/list (default: 60)
}
