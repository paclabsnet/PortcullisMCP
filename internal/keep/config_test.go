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
)

// validBaseConfig returns a minimal Config that passes Validate().
func validBaseConfig() Config {
	return Config{
		Listen: ListenConfig{Address: "localhost:8080"},
		PDP:    PDPConfig{Endpoint: "http://opa:8181"},
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
			name:        "missing listen.address",
			mutate:      func(c *Config) { c.Listen.Address = "" },
			wantErr:     true,
			errContains: "listen.address is required",
		},
		{
			name:        "missing pdp.endpoint",
			mutate:      func(c *Config) { c.PDP.Endpoint = "" },
			wantErr:     true,
			errContains: "pdp.endpoint is required",
		},

		// --- identity.normalizer ---
		{
			name:    "normalizer empty string is valid",
			mutate:  func(c *Config) { c.Identity.Normalizer = "" },
			wantErr: false,
		},
		{
			name:    "normalizer strict is valid",
			mutate:  func(c *Config) { c.Identity.Normalizer = "strict" },
			wantErr: false,
		},
		{
			name:    "normalizer passthrough is valid",
			mutate:  func(c *Config) { c.Identity.Normalizer = "passthrough" },
			wantErr: false,
		},
		{
			name:    "normalizer oidc-verify is valid when issuer and jwks_url set",
			mutate: func(c *Config) {
				c.Identity.Normalizer = "oidc-verify"
				c.Identity.OIDCVerify.Issuer = "https://issuer.example.com"
				c.Identity.OIDCVerify.JWKSURL = "https://issuer.example.com/.well-known/jwks.json"
			},
			wantErr: false,
		},
		{
			name:        "normalizer typo is invalid",
			mutate:      func(c *Config) { c.Identity.Normalizer = "Strict" },
			wantErr:     true,
			errContains: `invalid identity.normalizer "Strict"`,
		},
		{
			name:        "normalizer unknown value is invalid",
			mutate:      func(c *Config) { c.Identity.Normalizer = "none" },
			wantErr:     true,
			errContains: `invalid identity.normalizer "none"`,
		},

		// --- oidc-verify sub-fields ---
		{
			name: "oidc-verify missing issuer",
			mutate: func(c *Config) {
				c.Identity.Normalizer = "oidc-verify"
				c.Identity.OIDCVerify.JWKSURL = "https://issuer.example.com/.well-known/jwks.json"
			},
			wantErr:     true,
			errContains: "identity.oidc_verify.issuer is required",
		},
		{
			name: "oidc-verify missing jwks_url",
			mutate: func(c *Config) {
				c.Identity.Normalizer = "oidc-verify"
				c.Identity.OIDCVerify.Issuer = "https://issuer.example.com"
			},
			wantErr:     true,
			errContains: "identity.oidc_verify.jwks_url is required",
		},

		// --- escalation.workflow.type ---
		{
			name:    "workflow type empty is valid",
			mutate:  func(c *Config) { c.Escalation.Workflow.Type = "" },
			wantErr: false,
		},
		{
			name:    "workflow type noop is valid",
			mutate:  func(c *Config) { c.Escalation.Workflow.Type = "noop" },
			wantErr: false,
		},
		{
			name:    "workflow type url is valid",
			mutate:  func(c *Config) { c.Escalation.Workflow.Type = "url" },
			wantErr: false,
		},
		{
			name: "workflow type servicenow is valid when instance set",
			mutate: func(c *Config) {
				c.Escalation.Workflow.Type = "servicenow"
				c.Escalation.Workflow.ServiceNow.Instance = "mycompany"
			},
			wantErr: false,
		},
		{
			name: "workflow type webhook is valid when url set",
			mutate: func(c *Config) {
				c.Escalation.Workflow.Type = "webhook"
				c.Escalation.Workflow.Webhook.URL = "https://hooks.example.com/portcullis"
			},
			wantErr: false,
		},
		{
			name:        "workflow type typo is invalid",
			mutate:      func(c *Config) { c.Escalation.Workflow.Type = "ServiceNow" },
			wantErr:     true,
			errContains: `invalid escalation.workflow.type "ServiceNow"`,
		},
		{
			name:        "workflow type unknown value is invalid",
			mutate:      func(c *Config) { c.Escalation.Workflow.Type = "jira" },
			wantErr:     true,
			errContains: `invalid escalation.workflow.type "jira"`,
		},

		// --- servicenow requires instance ---
		{
			name:        "servicenow missing instance",
			mutate:      func(c *Config) { c.Escalation.Workflow.Type = "servicenow" },
			wantErr:     true,
			errContains: "escalation.workflow.servicenow.instance is required",
		},

		// --- webhook requires url ---
		{
			name:        "webhook missing url",
			mutate:      func(c *Config) { c.Escalation.Workflow.Type = "webhook" },
			wantErr:     true,
			errContains: "escalation.workflow.webhook.url is required",
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
