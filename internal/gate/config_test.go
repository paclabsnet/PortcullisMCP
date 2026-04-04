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
	"strings"
	"testing"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
	"github.com/paclabsnet/PortcullisMCP/internal/shared/tlsutil"
)

// validBaseConfig returns a minimal valid Config so individual tests can vary
// exactly one field at a time without triggering unrelated errors.
func validBaseConfig() Config {
	return Config{
		Mode: "dev",
		Peers: PeersConfig{
			Keep: cfgloader.PeerAuth{Endpoint: "http://keep.example.com"},
		},
	}
}

func TestConfig_Validate_KeepEndpointRequired(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Peers.Keep.Endpoint = ""
	if _, err := cfg.Validate(nil); err == nil {
		t.Error("expected error when peers.keep.endpoint is empty")
	}
}

func TestConfig_Validate_IdentityStrategy(t *testing.T) {
	tests := []struct {
		strategy string
		wantErr  bool
	}{
		{"", false},
		{"os", false},
		{"oidc-file", true},  // token_file not set
		{"oidc-login", true}, // issuer_url not set
		{"ldap", true},
	}
	for _, tc := range tests {
		t.Run(tc.strategy, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.Identity.Strategy = tc.strategy
			_, err := cfg.Validate(nil)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestConfig_Validate_OIDCFileTokenFileRequired(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Identity.Strategy = "oidc-file"
	cfg.Identity.Config = map[string]any{"token_file": "/path/to/token"}
	if _, err := cfg.Validate(nil); err != nil {
		t.Errorf("expected no error with token_file set; got: %v", err)
	}
}

func TestConfig_Validate_OIDCLoginRequired(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Identity.Strategy = "oidc-login"
	cfg.Identity.Config = map[string]any{
		"issuer_url": "https://idp.example.com",
		"client_id":  "client-id",
	}
	if _, err := cfg.Validate(nil); err != nil {
		t.Errorf("expected no error with issuer_url and client_id set; got: %v", err)
	}
}

func TestConfig_Validate_ApprovalManagementStrategy(t *testing.T) {
	tests := []struct {
		strategy string
		wantErr  bool
	}{
		{"user-driven", false},
		{"proactive", false},
		{"Proactive", true},
		{"USER-DRIVEN", true},
		{"proactve", true},
		{"unknown", true},
	}

	for _, tc := range tests {
		t.Run(tc.strategy, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.Responsibility.Escalation.Strategy = tc.strategy
			if tc.strategy == "proactive" {
				cfg.Peers.Guard.Endpoints.ApprovalUI = "http://guard.example.com"
			}
			_, err := cfg.Validate(nil)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestConfig_Validate_ProactiveRequiresGuardEndpoint(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Responsibility.Escalation.Strategy = "proactive"
	cfg.Peers.Guard.Endpoints.ApprovalUI = ""
	if _, err := cfg.Validate(nil); err == nil {
		t.Error("expected error when proactive strategy set but peers.guard.endpoints.approval_ui is empty")
	}
}

func TestConfig_Validate_ProductionMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		prepare func(*Config)
		wantErr bool
	}{
		{
			"dev mode allows os identity",
			"dev",
			func(c *Config) { c.Identity.Strategy = "os" },
			false,
		},
		{
			"production mode rejects os identity",
			"production",
			func(c *Config) { c.Identity.Strategy = "os" },
			true,
		},
		{
			"production mode rejects auth none",
			"production",
			func(c *Config) {
				c.Server.Endpoints = map[string]cfgloader.EndpointConfig{
					"ui": {Listen: "localhost:7777", Auth: cfgloader.AuthSettings{Type: "none"}},
				}
			},
			true,
		},
		{
			"production mode rejects insecure non-loopback",
			"production",
			func(c *Config) {
				c.Server.Endpoints = map[string]cfgloader.EndpointConfig{
					"api": {
						Listen: "0.0.0.0:8080",
						Auth:   cfgloader.AuthSettings{Type: "bearer"},
					},
				}
			},
			true,
		},
		{
			"production mode allows secure non-loopback",
			"production",
			func(c *Config) {
				c.Server.Endpoints = map[string]cfgloader.EndpointConfig{
					"api": {
						Listen: "0.0.0.0:8080",
						Auth:   cfgloader.AuthSettings{Type: "bearer"},
						TLS:    tlsutil.TLSConfig{Cert: "c", Key: "k"},
					},
				}
			},
			false,
		},
		{
			"empty mode defaults to production",
			"",
			func(c *Config) { c.Identity.Strategy = "os" },
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.Mode = tc.mode
			tc.prepare(&cfg)
			_, err := cfg.Validate(nil)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// validMultiTenantConfig returns a minimal valid multi-tenant Config.
func validMultiTenantConfig() Config {
	return Config{
		Mode:    "dev",
		Tenancy: "multi",
		Server: cfgloader.ServerConfig{
			SessionTTL: 3600,
			Endpoints: map[string]cfgloader.EndpointConfig{
				MCPEndpoint: {Listen: "0.0.0.0:8443"},
			},
		},
		Peers: PeersConfig{
			Keep: cfgloader.PeerAuth{Endpoint: "http://keep.example.com"},
		},
		Identity: IdentityConfig{Strategy: "os"},
	}
}

func TestConfig_TenancyValidation(t *testing.T) {
	t.Run("invalid tenancy value", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Tenancy = "enterprise"
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "invalid tenancy") {
			t.Errorf("expected 'invalid tenancy' error, got: %v", err)
		}
	})

	t.Run("empty tenancy defaults to single (valid)", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Tenancy = ""
		if _, err := cfg.Validate(nil); err != nil {
			t.Errorf("empty tenancy should be valid; got: %v", err)
		}
	})

	t.Run("single tenancy explicit (valid)", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Tenancy = "single"
		if _, err := cfg.Validate(nil); err != nil {
			t.Errorf("tenancy single should be valid; got: %v", err)
		}
	})

	t.Run("multi: valid minimal config", func(t *testing.T) {
		cfg := validMultiTenantConfig()
		if _, err := cfg.Validate(nil); err != nil {
			t.Errorf("valid multi-tenant config should pass; got: %v", err)
		}
	})

	t.Run("multi: mcp listen required", func(t *testing.T) {
		cfg := validMultiTenantConfig()
		delete(cfg.Server.Endpoints, MCPEndpoint)
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "server.endpoints.mcp.listen") {
			t.Errorf("expected mcp listen error, got: %v", err)
		}
	})

	t.Run("multi: localfs must be disabled", func(t *testing.T) {
		cfg := validMultiTenantConfig()
		cfg.Responsibility.Tools.LocalFS.Enabled = true
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "portcullis-localfs.enabled") {
			t.Errorf("expected localfs disabled error, got: %v", err)
		}
	})

	t.Run("multi: escalation must be disabled", func(t *testing.T) {
		cfg := validMultiTenantConfig()
		cfg.Responsibility.Escalation.Enabled = true
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "escalation.enabled") {
			t.Errorf("expected escalation disabled error, got: %v", err)
		}
	})

	t.Run("multi: management_ui must not exist", func(t *testing.T) {
		cfg := validMultiTenantConfig()
		cfg.Server.Endpoints[ManagementUIEndpoint] = cfgloader.EndpointConfig{Listen: "127.0.0.1:7777"}
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "management_ui") {
			t.Errorf("expected management_ui error, got: %v", err)
		}
	})

	t.Run("multi: guard must not be configured (approval_ui)", func(t *testing.T) {
		cfg := validMultiTenantConfig()
		cfg.Peers.Guard.Endpoints.ApprovalUI = "http://guard.example.com"
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "peers.guard") {
			t.Errorf("expected peers.guard error, got: %v", err)
		}
	})

	t.Run("multi: guard must not be configured (endpoint)", func(t *testing.T) {
		cfg := validMultiTenantConfig()
		cfg.Peers.Guard.Endpoint = "http://guard.example.com"
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "peers.guard") {
			t.Errorf("expected peers.guard error, got: %v", err)
		}
	})

	t.Run("multi: oidc-login not allowed", func(t *testing.T) {
		cfg := validMultiTenantConfig()
		cfg.Identity.Strategy = "oidc-login"
		cfg.Identity.Config = map[string]any{
			"issuer_url": "https://idp.example.com",
			"client_id":  "c",
		}
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "oidc-login") {
			t.Errorf("expected oidc-login error, got: %v", err)
		}
	})

	t.Run("multi: session_ttl must be > 0", func(t *testing.T) {
		cfg := validMultiTenantConfig()
		cfg.Server.SessionTTL = 0
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "session_ttl") {
			t.Errorf("expected session_ttl error, got: %v", err)
		}
	})

	t.Run("multi: redis without addr rejected", func(t *testing.T) {
		cfg := validMultiTenantConfig()
		cfg.Operations.Storage.Backend = "redis"
		cfg.Operations.Storage.Config = map[string]any{} // no addr
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "addr") {
			t.Errorf("expected redis addr error, got: %v", err)
		}
	})

	t.Run("multi: redis with addr valid", func(t *testing.T) {
		cfg := validMultiTenantConfig()
		cfg.Operations.Storage.Backend = "redis"
		cfg.Operations.Storage.Config = map[string]any{"addr": "redis:6379"}
		if _, err := cfg.Validate(nil); err != nil {
			t.Errorf("redis with addr should be valid; got: %v", err)
		}
	})

	t.Run("single: escalation enabled without guard rejected", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Tenancy = "single"
		cfg.Responsibility.Escalation.Enabled = true
		// No guard configured
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "peers.guard") {
			t.Errorf("expected peers.guard error, got: %v", err)
		}
	})

	t.Run("single: escalation enabled with guard valid", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Tenancy = "single"
		cfg.Responsibility.Escalation.Enabled = true
		cfg.Peers.Guard.Endpoints.ApprovalUI = "http://guard.example.com"
		if _, err := cfg.Validate(nil); err != nil {
			t.Errorf("single with escalation+guard should be valid; got: %v", err)
		}
	})
}
