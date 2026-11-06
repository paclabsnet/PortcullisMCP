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
	"context"
	"os"
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

	// --- DCR (Dynamic Client Registration) ---
	t.Run("oauth with dcr enabled does not require static client_id", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Responsibility.Backends = []BackendConfig{
			{
				Name: "test-backend",
				Type: "http",
				URL:  "http://backend.internal/mcp",
				UserIdentity: BackendUserIdentity{
					Type: "oauth",
					OAuth: BackendOAuth{
						CallbackURL: "https://keep.example.com/oauth/callback",
						Scopes:      []string{"openid"},
						DCR: BackendDCR{
							Enabled:              true,
							RegistrationEndpoint: "https://idp.example.com/connect/register",
							ClientName:           "Portcullis",
						},
					},
				},
			},
		}
		if _, err := cfg.Validate(nil); err != nil {
			t.Errorf("oauth with dcr enabled should be valid without client_id, got: %v", err)
		}
	})

	t.Run("oauth without dcr still requires static client_id", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Responsibility.Backends = []BackendConfig{
			{
				Name: "test-backend",
				Type: "http",
				URL:  "http://backend.internal/mcp",
				UserIdentity: BackendUserIdentity{
					Type: "oauth",
					OAuth: BackendOAuth{
						CallbackURL: "https://keep.example.com/oauth/callback",
						Scopes:      []string{"openid"},
						// DCR not enabled; client_id is empty
					},
				},
			},
		}
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "client_id") {
			t.Errorf("oauth without dcr should require client_id, got: %v", err)
		}
	})

	t.Run("dcr struct fields are parsed correctly", func(t *testing.T) {
		dcr := BackendDCR{
			Enabled:              true,
			RegistrationEndpoint: "https://idp.example.com/connect/register",
			InitialAccessToken:   "iat-token",
			SoftwareStatement:    "eyJhbGciOiJSUzI1NiJ9.e30.sig",
			ClientName:           "Portcullis Keep",
			Timeout:              15 * 1000000000, // 15s in nanoseconds
			FailureCacheTTL:      300 * 1000000000,
		}
		if !dcr.Enabled {
			t.Error("expected Enabled to be true")
		}
		if dcr.RegistrationEndpoint != "https://idp.example.com/connect/register" {
			t.Errorf("unexpected RegistrationEndpoint: %q", dcr.RegistrationEndpoint)
		}
		if dcr.ClientName != "Portcullis Keep" {
			t.Errorf("unexpected ClientName: %q", dcr.ClientName)
		}
	})

	t.Run("absent gate_static_policy block is valid (feature disabled)", func(t *testing.T) {
		cfg := validBaseConfig()
		// GateStaticPolicy is zero-valued — strategy is empty.
		if _, err := cfg.Validate(nil); err != nil {
			t.Errorf("empty gate_static_policy should be valid (disabled), got: %v", err)
		}
	})

	t.Run("gate_static_policy with opa strategy and endpoint is valid", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Responsibility.GateStaticPolicy = GateStaticPolicyConfig{
			PolicyConfig: PolicyConfig{
				Strategy: "opa",
				Config:   map[string]any{"endpoint": "http://opa:8181/v1/data/portcullis/gate_static_config"},
			},
		}
		if _, err := cfg.Validate(nil); err != nil {
			t.Errorf("configured gate_static_policy should be valid, got: %v", err)
		}
	})

	t.Run("gate_static_policy with opa strategy but no endpoint is invalid", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Responsibility.GateStaticPolicy = GateStaticPolicyConfig{
			PolicyConfig: PolicyConfig{Strategy: "opa"},
		}
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "gate_static_policy") {
			t.Errorf("expected gate_static_policy endpoint error, got: %v", err)
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

func TestKeepConfig_RemoteSinkProductionSecurity(t *testing.T) {
	prodBase := func() Config {
		c := validBaseConfig()
		c.Mode = "production"
		c.Identity.Strategy = "oidc-verify"
		c.Identity.Config = map[string]any{
			"issuer":   "https://issuer.example.com",
			"jwks_url": "https://issuer.example.com/keys",
		}
		c.Server.Endpoints["main"] = cfgloader.EndpointConfig{
			Listen: "localhost:8080",
			Auth:   cfgloader.AuthSettings{Type: "bearer", Credentials: cfgloader.AuthCredentials{BearerToken: "tok"}},
			TLS:    tlsutil.TLSConfig{Cert: "cert.pem", Key: "key.pem"},
		}
		return c
	}

	t.Run("http sink with https passes production", func(t *testing.T) {
		c := prodBase()
		c.MCPActivityLog = cfgloader.MCPActivityLogConfig{
			Enabled: true,
			Sink:    "http",
			HTTP: cfgloader.HTTPActivitySinkConfig{
				URL:      "https://siem.internal/ingest",
				Encoding: "ndjson",
				Auth:     cfgloader.HTTPActivityAuthConfig{Type: "bearer", Token: "tok"},
			},
		}
		_, err := c.Validate(nil)
		if err != nil {
			t.Errorf("unexpected error for valid production http sink: %v", err)
		}
	})

	cases := []struct {
		name        string
		mutateSink  func(*Config)
		errContains string
	}{
		{
			name: "http sink with http:// rejected",
			mutateSink: func(c *Config) {
				c.MCPActivityLog = cfgloader.MCPActivityLogConfig{
					Enabled: true, Sink: "http",
					HTTP: cfgloader.HTTPActivitySinkConfig{
						URL: "http://siem.internal/ingest", Encoding: "ndjson",
						Auth: cfgloader.HTTPActivityAuthConfig{Type: "none"},
					},
				}
			},
			errContains: "must use https://",
		},
		{
			name: "http sink with insecure_skip_verify rejected",
			mutateSink: func(c *Config) {
				c.MCPActivityLog = cfgloader.MCPActivityLogConfig{
					Enabled: true, Sink: "http",
					HTTP: cfgloader.HTTPActivitySinkConfig{
						URL: "https://siem.internal/ingest", Encoding: "ndjson",
						Auth: cfgloader.HTTPActivityAuthConfig{Type: "none"},
						TLS:  cfgloader.ActivityTLSConfig{InsecureSkipVerify: true},
					},
				}
			},
			errContains: "insecure_skip_verify must be false",
		},
		{
			name: "otlp sink with http:// rejected",
			mutateSink: func(c *Config) {
				c.MCPActivityLog = cfgloader.MCPActivityLogConfig{
					Enabled: true, Sink: "otlp",
					OTLP: cfgloader.OTLPActivitySinkConfig{
						Endpoint: "http://otel.internal:4318/v1/logs",
						Auth:     cfgloader.HTTPActivityAuthConfig{Type: "none"},
					},
				}
			},
			errContains: "must use https://",
		},
		{
			name: "otlp sink with insecure_skip_verify rejected",
			mutateSink: func(c *Config) {
				c.MCPActivityLog = cfgloader.MCPActivityLogConfig{
					Enabled: true, Sink: "otlp",
					OTLP: cfgloader.OTLPActivitySinkConfig{
						Endpoint: "https://otel.internal:4318/v1/logs",
						Auth:     cfgloader.HTTPActivityAuthConfig{Type: "none"},
						TLS:      cfgloader.ActivityTLSConfig{InsecureSkipVerify: true},
					},
				}
			},
			errContains: "insecure_skip_verify must be false",
		},
		{
			name: "http sink disabled in production: no TLS check",
			mutateSink: func(c *Config) {
				c.MCPActivityLog = cfgloader.MCPActivityLogConfig{
					Enabled: false, Sink: "http",
					HTTP: cfgloader.HTTPActivitySinkConfig{
						URL: "http://plaintext.internal/ingest", Encoding: "ndjson",
						Auth: cfgloader.HTTPActivityAuthConfig{Type: "none"},
					},
				}
			},
			errContains: "", // disabled sink is not validated for TLS
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := prodBase()
			tc.mutateSink(&c)
			_, err := c.Validate(nil)
			if tc.errContains == "" {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.errContains) {
				t.Errorf("expected error containing %q, got: %v", tc.errContains, err)
			}
		})
	}
}

func TestKeepConfig_RemoteActivityLogSinks(t *testing.T) {
	t.Run("valid http sink config with defaults", func(t *testing.T) {
		yamlConfig := `
mode: "dev"
server:
  endpoints:
    main:
      listen: "localhost:8080"
responsibility:
  policy:
    strategy: "opa"
    config:
      endpoint: "http://opa:8181"
identity:
  strategy: "passthrough"
mcp_activity_log:
  enabled: true
  sink: "http"
  http:
    url: "https://splunk.internal:8088/services/collector/raw"
    encoding: "json_array"
    auth:
      type: "splunk"
      token: "static-token-123"
    headers:
      X-Test: "custom"
`
		tmp, err := os.CreateTemp("", "keep-remote-*.yaml")
		if err != nil {
			t.Fatalf("temp: %v", err)
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write([]byte(yamlConfig)); err != nil {
			t.Fatalf("write: %v", err)
		}
		tmp.Close()

		cfg, _, err := LoadConfig(context.Background(), tmp.Name())
		if err != nil {
			t.Fatalf("load failed: %v", err)
		}
		act := cfg.MCPActivityLog
		if act.Sink != "http" {
			t.Errorf("expected sink http, got %q", act.Sink)
		}
		if act.HTTP.URL != "https://splunk.internal:8088/services/collector/raw" {
			t.Errorf("unexpected URL: %q", act.HTTP.URL)
		}
		if act.HTTP.Encoding != "json_array" {
			t.Errorf("expected encoding json_array, got %q", act.HTTP.Encoding)
		}
		if act.HTTP.Auth.Type != "splunk" || act.HTTP.Auth.Token != "static-token-123" {
			t.Errorf("unexpected auth: %+v", act.HTTP.Auth)
		}
		if act.HTTP.BatchSize != cfgloader.DefaultBatchSize {
			t.Errorf("unexpected BatchSize: %d", act.HTTP.BatchSize)
		}
		if act.HTTP.MaxQueuedBatches != cfgloader.DefaultMaxQueuedBatches {
			t.Errorf("unexpected MaxQueuedBatches: %d", act.HTTP.MaxQueuedBatches)
		}
		if act.HTTP.FlushIntervalMS != cfgloader.DefaultFlushIntervalMS {
			t.Errorf("unexpected FlushIntervalMS: %d", act.HTTP.FlushIntervalMS)
		}
	})

	t.Run("validation rejections", func(t *testing.T) {
		cases := []struct {
			name        string
			mutate      func(c *cfgloader.MCPActivityLogConfig)
			errContains string
		}{
			{
				name: "invalid sink type",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "invalid_sink"
				},
				errContains: "unknown sink type",
			},
			{
				name: "missing http url",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "http"
					c.HTTP.URL = ""
				},
				errContains: "http url is required",
			},
			{
				name: "invalid http encoding",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "http"
					c.HTTP.URL = "https://example.com"
					c.HTTP.Encoding = "xml"
				},
				errContains: "invalid encoding",
			},
			{
				name: "invalid auth type",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "http"
					c.HTTP.URL = "https://example.com"
					c.HTTP.Auth.Type = "oauth1"
				},
				errContains: "unsupported auth type",
			},
			{
				name: "missing auth token when type specified",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "http"
					c.HTTP.URL = "https://example.com"
					c.HTTP.Auth.Type = "bearer"
					c.HTTP.Auth.Token = ""
				},
				errContains: "auth token required",
			},
			{
				name: "invalid batch size",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "http"
					c.HTTP.URL = "https://example.com"
					c.HTTP.BatchSize = 0
				},
				errContains: "batch_size must be > 0",
			},
			{
				name: "http zero max_queued_batches",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "http"
					c.HTTP.URL = "https://example.com"
					c.HTTP.MaxQueuedBatches = 0
				},
				errContains: "max_queued_batches must be > 0",
			},
			{
				name: "http negative max_queued_batches",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "http"
					c.HTTP.URL = "https://example.com"
					c.HTTP.MaxQueuedBatches = -1
				},
				errContains: "max_queued_batches must be > 0",
			},
			{
				name: "http zero flush_interval_ms",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "http"
					c.HTTP.URL = "https://example.com"
					c.HTTP.FlushIntervalMS = 0
				},
				errContains: "flush_interval_ms must be > 0",
			},
			{
				name: "http negative flush_interval_ms",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "http"
					c.HTTP.URL = "https://example.com"
					c.HTTP.FlushIntervalMS = -1
				},
				errContains: "flush_interval_ms must be > 0",
			},
			{
				name: "http zero timeout_ms",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "http"
					c.HTTP.URL = "https://example.com"
					c.HTTP.TimeoutMS = 0
				},
				errContains: "timeout_ms must be > 0",
			},
			{
				name: "http negative max_retries",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "http"
					c.HTTP.URL = "https://example.com"
					c.HTTP.MaxRetries = -1
				},
				errContains: "max_retries must be >= 0",
			},
			{
				name: "http negative retry_backoff_ms",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "http"
					c.HTTP.URL = "https://example.com"
					c.HTTP.RetryBackoffMS = -1
				},
				errContains: "retry_backoff_ms must be >= 0",
			},
			{
				name: "otlp zero max_queued_batches",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "otlp"
					c.OTLP.Endpoint = "https://otel:4318/v1/logs"
					c.OTLP.MaxQueuedBatches = 0
				},
				errContains: "max_queued_batches must be > 0",
			},
			{
				name: "otlp zero flush_interval_ms",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "otlp"
					c.OTLP.Endpoint = "https://otel:4318/v1/logs"
					c.OTLP.FlushIntervalMS = 0
				},
				errContains: "flush_interval_ms must be > 0",
			},
			{
				name: "otlp zero timeout_ms",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "otlp"
					c.OTLP.Endpoint = "https://otel:4318/v1/logs"
					c.OTLP.TimeoutMS = 0
				},
				errContains: "timeout_ms must be > 0",
			},
			{
				name: "otlp negative max_retries",
				mutate: func(c *cfgloader.MCPActivityLogConfig) {
					c.Sink = "otlp"
					c.OTLP.Endpoint = "https://otel:4318/v1/logs"
					c.OTLP.MaxRetries = -1
				},
				errContains: "max_retries must be >= 0",
			},
		}

		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				c := cfgloader.DefaultMCPActivityLogConfig()
				c.Enabled = true
				tc.mutate(&c)
				err := c.Validate()
				if err == nil || !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("expected error containing %q, got: %v", tc.errContains, err)
				}
			})
		}
	})
}
