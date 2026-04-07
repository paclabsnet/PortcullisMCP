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
	"github.com/paclabsnet/PortcullisMCP/internal/shared/tlsutil"
)

// validBaseConfig returns a minimal Config that passes Validate().
func validBaseConfig() Config {
	return Config{
		Mode: "dev",
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
		{
			name: "identity strategy hmac-verify is valid when secret set",
			mutate: func(c *Config) {
				c.Identity.Strategy = "hmac-verify"
				c.Identity.Config = map[string]any{
					"secret":    "a-sufficiently-long-test-secret",
					"algorithm": "HS256",
				}
			},
			wantErr: false,
		},
		{
			name: "hmac-verify missing secret is invalid",
			mutate: func(c *Config) {
				c.Identity.Strategy = "hmac-verify"
				c.Identity.Config = map[string]any{
					"algorithm": "HS256",
				}
			},
			wantErr:     true,
			errContains: "identity.hmac_verify.secret is required",
		},
		{
			name: "hmac-verify invalid algorithm is rejected",
			mutate: func(c *Config) {
				c.Identity.Strategy = "hmac-verify"
				c.Identity.Config = map[string]any{
					"secret":    "a-sufficiently-long-test-secret",
					"algorithm": "RS256",
				}
			},
			wantErr:     true,
			errContains: "invalid identity.hmac_verify.algorithm",
		},
		{
			name: "hmac-verify empty algorithm defaults to HS256",
			mutate: func(c *Config) {
				c.Identity.Strategy = "hmac-verify"
				c.Identity.Config = map[string]any{
					"secret": "a-sufficiently-long-test-secret",
				}
			},
			wantErr: false,
		},
		{
			name: "hmac-verify HS384 is valid",
			mutate: func(c *Config) {
				c.Identity.Strategy = "hmac-verify"
				c.Identity.Config = map[string]any{
					"secret":    "a-sufficiently-long-test-secret",
					"algorithm": "HS384",
				}
			},
			wantErr: false,
		},
		{
			name: "hmac-verify HS512 is valid",
			mutate: func(c *Config) {
				c.Identity.Strategy = "hmac-verify"
				c.Identity.Config = map[string]any{
					"secret":    "a-sufficiently-long-test-secret",
					"algorithm": "HS512",
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

		// --- peers.normalization ---
		{
			name: "normalization endpoint http rejected in production mode",
			mutate: func(c *Config) {
				c.Mode = "production"
				c.Identity.Strategy = "oidc-verify"
				c.Identity.Config = map[string]any{
					"issuer":   "https://issuer.example.com",
					"jwks_url": "https://issuer.example.com/keys",
				}
				c.Server.Endpoints["main"] = cfgloader.EndpointConfig{
					Listen: "localhost:8080",
					Auth:   cfgloader.AuthSettings{Type: "bearer"},
					TLS:    tlsutil.TLSConfig{Cert: "cert.pem", Key: "key.pem"},
				}
				c.Peers.Normalization.Endpoint = "http://mapper.internal/map"
			},
			wantErr:     true,
			errContains: "peers.normalization.endpoint must use https://",
		},
		{
			name: "normalization endpoint https accepted in production mode",
			mutate: func(c *Config) {
				c.Mode = "production"
				c.Identity.Strategy = "oidc-verify"
				c.Identity.Config = map[string]any{
					"issuer":   "https://issuer.example.com",
					"jwks_url": "https://issuer.example.com/keys",
				}
				c.Server.Endpoints["main"] = cfgloader.EndpointConfig{
					Listen: "localhost:8080",
					Auth:   cfgloader.AuthSettings{Type: "bearer"},
					TLS:    tlsutil.TLSConfig{Cert: "cert.pem", Key: "key.pem"},
				}
				c.Peers.Normalization.Endpoint = "https://mapper.internal/map"
			},
			wantErr: false,
		},
		{
			name: "normalization cache and validation fields are decoded from identity.config",
			mutate: func(c *Config) {
				c.Identity.Strategy = "passthrough"
				c.Identity.Config = map[string]any{
					"cache_ttl":            600,
					"cache_max_entries":    5000,
					"max_userid_length":    256,
					"max_group_name_length": 128,
					"max_groups_count":     100,
				}
			},
			wantErr: false,
		},

		// --- production mode safety ---
		{
			name: "production mode rejects passthrough identity",
			mutate: func(c *Config) {
				c.Mode = "production"
				c.Identity.Strategy = "passthrough"
			},
			wantErr:     true,
			errContains: "identity.strategy \"passthrough\" is not allowed in production mode",
		},
		{
			name: "production mode rejects noop policy",
			mutate: func(c *Config) {
				c.Mode = "production"
				c.Identity.Strategy = "oidc-verify"
				c.Identity.Config = map[string]any{
					"issuer":   "https://issuer.example.com",
					"jwks_url": "https://issuer.example.com/keys",
				}
				c.Responsibility.Policy.Strategy = "noop"
			},
			wantErr:     true,
			errContains: "policy.strategy \"noop\" is not allowed in production mode",
		},
		{
			name: "production mode rejects insecure jwks url",
			mutate: func(c *Config) {
				c.Mode = "production"
				c.Identity.Strategy = "oidc-verify"
				c.Identity.Config = map[string]any{
					"issuer":                  "https://issuer.example.com",
					"jwks_url":                "http://issuer.example.com/keys",
					"allow_insecure_jwks_url": true,
				}
			},
			wantErr:     true,
			errContains: "identity.config.allow_insecure_jwks_url is not allowed in production mode",
		},
		{
			name: "production mode rejects auth none",
			mutate: func(c *Config) {
				c.Mode = "production"
				c.Identity.Strategy = "oidc-verify"
				c.Identity.Config = map[string]any{
					"issuer":   "https://issuer.example.com",
					"jwks_url": "https://issuer.example.com/keys",
				}
				c.Server.Endpoints["main"] = cfgloader.EndpointConfig{
					Listen: "localhost:8080",
					Auth:   cfgloader.AuthSettings{Type: "none"},
				}
			},
			wantErr:     true,
			errContains: "auth.type \"none\" for endpoint \"main\" is not allowed in production mode",
		},
		{
			name: "production mode rejects insecure non-loopback",
			mutate: func(c *Config) {
				c.Mode = "production"
				c.Identity.Strategy = "oidc-verify"
				c.Identity.Config = map[string]any{
					"issuer":   "https://issuer.example.com",
					"jwks_url": "https://issuer.example.com/keys",
				}
				c.Server.Endpoints["main"] = cfgloader.EndpointConfig{
					Listen: "0.0.0.0:8080",
					Auth:   cfgloader.AuthSettings{Type: "bearer"},
				}
			},
			wantErr:     true,
			errContains: "TLS is required for non-loopback endpoint \"main\" in production mode",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := validBaseConfig()
			tc.mutate(&cfg)
			_, err := cfg.Validate(nil)
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

func TestConfigValidate_PostureWarnings(t *testing.T) {
	findWarning := func(report cfgloader.PostureReport, property string) (cfgloader.PostureFinding, bool) {
		for _, f := range report.Findings {
			if f.Property == property && f.Status == "WARN" {
				return f, true
			}
		}
		return cfgloader.PostureFinding{}, false
	}

	t.Run("passthrough identity emits warning mentioning hmac-verify", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Identity.Strategy = "passthrough"
		report, err := cfg.Validate(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		f, ok := findWarning(report, "identity.strategy")
		if !ok {
			t.Fatal("expected WARN posture finding for identity.strategy, got none")
		}
		if !strings.Contains(f.Recommendation, "hmac-verify") {
			t.Errorf("warning should mention hmac-verify, got: %q", f.Recommendation)
		}
	})

	t.Run("hmac-verify identity does not emit passthrough warning", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Identity.Strategy = "hmac-verify"
		cfg.Identity.Config = map[string]any{
			"secret":    "a-sufficiently-long-test-secret",
			"algorithm": "HS256",
		}
		report, err := cfg.Validate(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := findWarning(report, "identity.strategy"); ok {
			t.Error("hmac-verify should not trigger passthrough warning")
		}
	})

	t.Run("passthrough with normalization endpoint emits inactive-webhook warning", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Identity.Strategy = "passthrough"
		cfg.Peers.Normalization.Endpoint = "http://mapper.internal/map"
		report, err := cfg.Validate(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		f, ok := findWarning(report, "peers.normalization.endpoint")
		if !ok {
			t.Fatal("expected WARN posture finding for peers.normalization.endpoint, got none")
		}
		if !strings.Contains(f.Recommendation, "no effect") {
			t.Errorf("warning should mention 'no effect', got: %q", f.Recommendation)
		}
	})

	t.Run("oidc-verify with normalization endpoint does not emit inactive-webhook warning", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Identity.Strategy = "oidc-verify"
		cfg.Identity.Config = map[string]any{
			"issuer":   "https://issuer.example.com",
			"jwks_url": "https://issuer.example.com/keys",
		}
		cfg.Peers.Normalization.Endpoint = "http://mapper.internal/map"
		report, err := cfg.Validate(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := findWarning(report, "peers.normalization.endpoint"); ok {
			t.Error("oidc-verify with normalization endpoint should not trigger inactive-webhook warning")
		}
	})
}
