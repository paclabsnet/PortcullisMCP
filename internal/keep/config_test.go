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

//go:build !integration

package keep

import (
	"strings"
	"testing"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// validBaseConfig returns a minimal Config that passes Validate().
func validBaseConfig() Config {
	return Config{
		Server: cfgloader.ServerConfig{
			Endpoints: map[string]cfgloader.EndpointConfig{
				"main": {Listen: "localhost:8080"},
			},
		},
		Responsibility: ResponsibilityConfig{
			Policy: PolicyConfig{Strategy: "opa", Config: map[string]any{"endpoint": "http://opa:8181"}},
		},
		Identity: IdentityConfig{Strategy: "passthrough"},
	}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		mutate      func(*Config)
		wantErr     bool
		errContains string
	}{
		// --- required fields ---
		{
			name:    "valid base config",
			mutate:  func(c *Config) {},
			wantErr: false,
		},
		{
			name: "missing main endpoint",
			mutate: func(c *Config) {
				delete(c.Server.Endpoints, "main")
			},
			wantErr:     true,
			errContains: "server.endpoints.main is required",
		},
		{
			name: "missing pdp endpoint when strategy is opa",
			mutate: func(c *Config) {
				c.Responsibility.Policy.Config = map[string]any{"endpoint": ""}
			},
			wantErr:     true,
			errContains: "policy.config.endpoint is required",
		},
		{
			name: "noop pdp does not require endpoint",
			mutate: func(c *Config) {
				c.Responsibility.Policy.Strategy = "noop"
				c.Responsibility.Policy.Config = nil
			},
			wantErr: false,
		},

		// --- identity.strategy ---
		{
			name:    "identity strategy empty is invalid",
			mutate:  func(c *Config) { c.Identity.Strategy = "" },
			wantErr: true,
		},
		{
			name:    "identity strategy passthrough is valid",
			mutate:  func(c *Config) { c.Identity.Strategy = "passthrough" },
			wantErr: false,
		},
		{
			name: "identity strategy oidc-verify is valid when issuer and jwks_url set",
			mutate: func(c *Config) {
				c.Identity.Strategy = "oidc-verify"
				c.Identity.Config = map[string]any{
					"issuer":   "https://issuer.example.com",
					"jwks_url": "https://issuer.example.com/.well-known/jwks.json",
				}
			},
			wantErr: false,
		},

		// --- responsibility.workflow.strategy ---
		{
			name:    "workflow strategy empty is valid",
			mutate:  func(c *Config) { c.Responsibility.Workflow.Strategy = "" },
			wantErr: false,
		},
		{
			name:    "workflow strategy noop is valid",
			mutate:  func(c *Config) { c.Responsibility.Workflow.Strategy = "noop" },
			wantErr: false,
		},
		{
			name: "workflow strategy servicenow is valid when instance set",
			mutate: func(c *Config) {
				c.Responsibility.Workflow.Strategy = "servicenow"
				c.Responsibility.Workflow.Config = map[string]any{"instance": "mycompany"}
			},
			wantErr: false,
		},
		{
			name: "workflow strategy webhook is valid when url set",
			mutate: func(c *Config) {
				c.Responsibility.Workflow.Strategy = "webhook"
				c.Responsibility.Workflow.Config = map[string]any{"url": "https://hooks.example.com/portcullis"}
			},
			wantErr: false,
		},
		{
			name:        "workflow strategy unknown value is invalid",
			mutate:      func(c *Config) { c.Responsibility.Workflow.Strategy = "jira" },
			wantErr:     true,
			errContains: `invalid escalation.strategy "jira"`,
		},

		// --- servicenow requires instance ---
		{
			name: "servicenow missing instance",
			mutate: func(c *Config) {
				c.Responsibility.Workflow.Strategy = "servicenow"
				c.Responsibility.Workflow.Config = nil
			},
			wantErr:     true,
			errContains: "escalation.config.instance is required",
		},

		// --- webhook requires url ---
		{
			name: "webhook missing url",
			mutate: func(c *Config) {
				c.Responsibility.Workflow.Strategy = "webhook"
				c.Responsibility.Workflow.Config = nil
			},
			wantErr:     true,
			errContains: "escalation.config.url is required",
		},
	}


	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := validBaseConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %q", err.Error())
				}
			}
		})
	}
}
