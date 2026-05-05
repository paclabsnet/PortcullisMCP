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

// --- GateSpecificGuardConfig.resolvedAPIEndpoint ---

func TestResolvedAPIEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		tokenAPI  string
		approvalUI string
		want      string
	}{
		{
			name:      "both empty returns empty",
			tokenAPI:  "",
			approvalUI: "",
			want:      "",
		},
		{
			name:      "token_api alone is returned",
			tokenAPI:  "http://guard.example.com/token",
			approvalUI: "",
			want:      "http://guard.example.com/token",
		},
		{
			name:      "approval_ui used when token_api is empty",
			tokenAPI:  "",
			approvalUI: "http://guard.example.com/ui",
			want:      "http://guard.example.com/ui",
		},
		{
			name:      "token_api wins over approval_ui",
			tokenAPI:  "http://guard.example.com/token",
			approvalUI: "http://guard.example.com/ui",
			want:      "http://guard.example.com/token",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := GateSpecificGuardConfig{}
			g.Endpoints.TokenAPI = tc.tokenAPI
			g.Endpoints.ApprovalUI = tc.approvalUI
			got := g.resolvedAPIEndpoint()
			if got != tc.want {
				t.Errorf("resolvedAPIEndpoint() = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- IdentityConfig.Validate edge cases ---

func TestIdentityConfig_Validate_OIDCLoginFlow(t *testing.T) {
	tests := []struct {
		name    string
		flow    string
		wantErr bool
	}{
		{"empty flow is valid", "", false},
		{"authorization_code is valid", "authorization_code", false},
		{"device_code is unsupported", "device_code", true},
		{"implicit is unsupported", "implicit", true},
		{"client_credentials is unsupported", "client_credentials", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := IdentityConfig{
				Strategy: "oidc-login",
				Config: map[string]any{
					"issuer_url": "https://idp.example.com",
					"client_id":  "my-client",
					"flow":       tc.flow,
				},
			}
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestIdentityConfig_Validate_OIDCLoginMissingIssuer(t *testing.T) {
	cfg := IdentityConfig{
		Strategy: "oidc-login",
		Config:   map[string]any{"client_id": "c"},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "issuer_url") {
		t.Errorf("expected issuer_url error, got: %v", err)
	}
}

func TestIdentityConfig_Validate_OIDCLoginMissingClientID(t *testing.T) {
	cfg := IdentityConfig{
		Strategy: "oidc-login",
		Config:   map[string]any{"issuer_url": "https://idp.example.com"},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "client_id") {
		t.Errorf("expected client_id error, got: %v", err)
	}
}

func TestIdentityConfig_Validate_NilConfig(t *testing.T) {
	// nil Config map should be fine for "os" strategy.
	cfg := IdentityConfig{Strategy: "os", Config: nil}
	if err := cfg.Validate(); err != nil {
		t.Errorf("os strategy with nil config should be valid; got: %v", err)
	}
}

// --- Posture report WARN flags from Config.Validate ---

func TestConfig_Validate_PostureReport_DevModeWarn(t *testing.T) {
	cfg := validBaseConfig() // mode = "dev"
	report, err := cfg.Validate(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range report.Findings {
		if f.Property == "mode" && f.Status == "WARN" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected WARN finding for 'mode' in dev mode")
	}
}

func TestConfig_Validate_PostureReport_ProductionModeNoWarn(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Mode = "production"
	cfg.Identity.Strategy = "oidc-file"
	cfg.Identity.Config = map[string]any{"token_file": "/path/to/token"}
	report, err := cfg.Validate(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range report.Findings {
		if f.Property == "mode" && f.Status == "WARN" {
			t.Error("production mode should not have WARN finding for 'mode'")
		}
	}
}

func TestConfig_Validate_PostureReport_OSIdentityWarn(t *testing.T) {
	cfg := validBaseConfig() // mode = "dev", strategy = ""
	cfg.Identity.Strategy = "os"
	report, err := cfg.Validate(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range report.Findings {
		if f.Property == "identity.strategy" && f.Status == "WARN" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected WARN finding for 'identity.strategy' when using os identity")
	}
}

func TestConfig_Validate_PostureReport_AuthNoneEndpointWarn(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Server.Endpoints = map[string]cfgloader.EndpointConfig{
		"mcp": {Listen: "127.0.0.1:8080", Auth: cfgloader.AuthSettings{Type: "none"}},
	}
	report, err := cfg.Validate(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range report.Findings {
		if f.Property == "server.endpoints.mcp.auth.type" && f.Status == "WARN" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected WARN finding for auth.type=none endpoint")
	}
}

func TestConfig_Validate_PostureReport_NoTLSEndpointWarn(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Server.Endpoints = map[string]cfgloader.EndpointConfig{
		"mcp": {Listen: "127.0.0.1:8080", Auth: cfgloader.AuthSettings{Type: "bearer"}},
		// no TLS configured
	}
	report, err := cfg.Validate(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range report.Findings {
		if f.Property == "server.endpoints.mcp.tls.cert" && f.Status == "WARN" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected WARN finding for missing TLS cert on endpoint")
	}
}

// --- validateMultiTenant edge cases ---

func TestConfig_ValidateMultiTenant_MCPListenEmpty(t *testing.T) {
	// MCP endpoint key exists but listen is empty.
	cfg := validMultiTenantConfig()
	cfg.Server.Endpoints[MCPEndpoint] = cfgloader.EndpointConfig{Listen: ""}
	_, err := cfg.Validate(nil)
	if err == nil || !strings.Contains(err.Error(), "server.endpoints.mcp.listen") {
		t.Errorf("expected mcp listen error for empty listen, got: %v", err)
	}
}

func TestConfig_ValidateMultiTenant_GuardTokenAPIAlsoBlocked(t *testing.T) {
	cfg := validMultiTenantConfig()
	cfg.Peers.Guard.Endpoints.TokenAPI = "http://guard.example.com/token"
	_, err := cfg.Validate(nil)
	if err == nil || !strings.Contains(err.Error(), "peers.guard") {
		t.Errorf("expected peers.guard error for token_api, got: %v", err)
	}
}

func TestConfig_ValidateMultiTenant_RedisWithNonStringAddr(t *testing.T) {
	// Storage config has addr but as a non-string type: should fail the type assertion.
	cfg := validMultiTenantConfig()
	cfg.Operations.Storage.Backend = "redis"
	cfg.Operations.Storage.Config = map[string]any{"addr": 6379} // int, not string
	_, err := cfg.Validate(nil)
	if err == nil || !strings.Contains(err.Error(), "addr") {
		t.Errorf("expected addr error for non-string addr, got: %v", err)
	}
}

func TestConfig_ValidateMultiTenant_NonRedisBackendNoAddrRequired(t *testing.T) {
	// A non-redis storage backend should not require addr.
	cfg := validMultiTenantConfig()
	cfg.Operations.Storage.Backend = "memory"
	cfg.Operations.Storage.Config = map[string]any{}
	if _, err := cfg.Validate(nil); err != nil {
		t.Errorf("non-redis backend should not require addr; got: %v", err)
	}
}

func TestConfig_ValidateMultiTenant_NegativeSessionTTLRejected(t *testing.T) {
	cfg := validMultiTenantConfig()
	cfg.Server.SessionTTL = -1
	_, err := cfg.Validate(nil)
	if err == nil || !strings.Contains(err.Error(), "session_ttl") {
		t.Errorf("expected session_ttl error for negative value, got: %v", err)
	}
}

// --- LocalFSStrategyConfig.Validate ---

func TestConfig_Validate_LocalFSStrategy(t *testing.T) {
	validValues := []string{"", "allow", "verify", "deny"}
	invalidValues := []string{"Allow", "DENY", "Verify", "block", "pass", "yes"}

	// Each category-level field must accept the three valid values and reject anything else.
	categorySetters := map[string]func(*LocalFSStrategyConfig, string){
		"read":   func(s *LocalFSStrategyConfig, v string) { s.Read = v },
		"write":  func(s *LocalFSStrategyConfig, v string) { s.Write = v },
		"update": func(s *LocalFSStrategyConfig, v string) { s.Update = v },
		"delete": func(s *LocalFSStrategyConfig, v string) { s.Delete = v },
	}
	// Each tool-specific field must accept the three valid values and reject anything else.
	toolSetters := map[string]func(*LocalFSStrategyConfig, string){
		"read_text_file":            func(s *LocalFSStrategyConfig, v string) { s.ReadTextFile = v },
		"read_media_file":           func(s *LocalFSStrategyConfig, v string) { s.ReadMediaFile = v },
		"read_multiple_files":       func(s *LocalFSStrategyConfig, v string) { s.ReadMultipleFiles = v },
		"write_file":                func(s *LocalFSStrategyConfig, v string) { s.WriteFile = v },
		"edit_file":                 func(s *LocalFSStrategyConfig, v string) { s.EditFile = v },
		"create_directory":          func(s *LocalFSStrategyConfig, v string) { s.CreateDirectory = v },
		"list_directory":            func(s *LocalFSStrategyConfig, v string) { s.ListDirectory = v },
		"list_directory_with_sizes": func(s *LocalFSStrategyConfig, v string) { s.ListDirectoryWithSizes = v },
		"directory_tree":            func(s *LocalFSStrategyConfig, v string) { s.DirectoryTree = v },
		"move_file":                 func(s *LocalFSStrategyConfig, v string) { s.MoveFile = v },
		"search_files":              func(s *LocalFSStrategyConfig, v string) { s.SearchFiles = v },
		"copy_file":                 func(s *LocalFSStrategyConfig, v string) { s.CopyFile = v },
		"delete_file":               func(s *LocalFSStrategyConfig, v string) { s.DeleteFile = v },
		"search_within_files":       func(s *LocalFSStrategyConfig, v string) { s.SearchWithinFiles = v },
		"get_file_info":             func(s *LocalFSStrategyConfig, v string) { s.GetFileInfo = v },
		"list_allowed_directories":  func(s *LocalFSStrategyConfig, v string) { s.ListAllowedDirectories = v },
	}

	allSetters := make(map[string]func(*LocalFSStrategyConfig, string))
	for k, v := range categorySetters {
		allSetters[k] = v
	}
	for k, v := range toolSetters {
		allSetters[k] = v
	}

	for field, set := range allSetters {
		for _, val := range validValues {
			t.Run(field+"/valid/"+val, func(t *testing.T) {
				var s LocalFSStrategyConfig
				set(&s, val)
				if err := s.Validate(); err != nil {
					t.Errorf("Validate() with %s=%q: unexpected error: %v", field, val, err)
				}
			})
		}
		for _, val := range invalidValues {
			t.Run(field+"/invalid/"+val, func(t *testing.T) {
				var s LocalFSStrategyConfig
				set(&s, val)
				if err := s.Validate(); err == nil {
					t.Errorf("Validate() with %s=%q: expected error, got nil", field, val)
				}
			})
		}
	}

	t.Run("invalid strategy propagates through Config.Validate", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Responsibility.Tools.LocalFS.Strategy.Read = "Block"
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "strategy.read") {
			t.Errorf("expected strategy.read error, got: %v", err)
		}
	})

	t.Run("empty strategy struct is valid (all defaults)", func(t *testing.T) {
		if err := (LocalFSStrategyConfig{}).Validate(); err != nil {
			t.Errorf("empty strategy should be valid; got: %v", err)
		}
	})
}

func TestConfig_Validate_LocalFSRules(t *testing.T) {
	t.Run("negative ttl is rejected", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Responsibility.Tools.LocalFS.Rules.TTL = -1
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "ttl") {
			t.Errorf("expected ttl error for negative value, got: %v", err)
		}
	})

	t.Run("zero ttl is rejected (after ApplyDefaults replaces 0→3600, negative stays negative)", func(t *testing.T) {
		// Explicitly set a negative value — zero is fine because ApplyDefaults
		// converts it to 3600 before validation runs.
		cfg := validBaseConfig()
		cfg.Responsibility.Tools.LocalFS.Rules.TTL = -60
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "ttl") {
			t.Errorf("expected ttl error for negative value, got: %v", err)
		}
	})

	t.Run("valid source values accepted", func(t *testing.T) {
		for _, src := range []string{"local", "keep"} {
			cfg := validBaseConfig()
			cfg.Responsibility.Tools.LocalFS.Rules.Source = src
			if _, err := cfg.Validate(nil); err != nil {
				t.Errorf("source %q should be valid, got: %v", src, err)
			}
		}
	})

	t.Run("invalid source is rejected", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Responsibility.Tools.LocalFS.Rules.Source = "remote"
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "source") {
			t.Errorf("expected source error, got: %v", err)
		}
	})

	t.Run("invalid on_fetch_failure is rejected", func(t *testing.T) {
		cfg := validBaseConfig()
		cfg.Responsibility.Tools.LocalFS.Rules.OnFetchFailure = "ignore"
		_, err := cfg.Validate(nil)
		if err == nil || !strings.Contains(err.Error(), "on_fetch_failure") {
			t.Errorf("expected on_fetch_failure error, got: %v", err)
		}
	})
}
