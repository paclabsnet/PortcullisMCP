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

package guard

import (
	"strings"
	"testing"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

func validBaseConfig() Config {
	return Config{
		Mode: "dev",
		Server: cfgloader.ServerConfig{
			Endpoints: map[string]cfgloader.EndpointConfig{
				"approval_ui": {Listen: "localhost:8080"},
				"token_api":   {Listen: "localhost:8081"},
			},
		},
		Responsibility: ResponsibilityConfig{
			Issuance: IssuanceConfig{
				ApprovalRequestVerificationKey: "test-keep-key",
				SigningKey:                     "test-token-key",
			},
		},
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*Config)
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid base config",
			mutate:  func(c *Config) {},
			wantErr: false,
		},
		{
			name: "missing ui endpoint",
			mutate: func(c *Config) {
				delete(c.Server.Endpoints, "approval_ui")
			},
			wantErr:     true,
			errContains: "server.endpoints.approval_ui is required",
		},
		{
			name: "missing api endpoint",
			mutate: func(c *Config) {
				delete(c.Server.Endpoints, "token_api")
			},
			wantErr:     true,
			errContains: "server.endpoints.token_api is required",
		},
		{
			name: "missing keep verification key",
			mutate: func(c *Config) {
				c.Responsibility.Issuance.ApprovalRequestVerificationKey = ""
			},
			wantErr:     true,
			errContains: "responsibility.issuance.approval_request_verification_key is required",
		},
		{
			name: "missing token signing key",
			mutate: func(c *Config) {
				c.Responsibility.Issuance.SigningKey = ""
			},
			wantErr:     true,
			errContains: "responsibility.issuance.signing_key is required",
		},

		// --- production mode safety ---
		{
			name: "production mode rejects auth none",
			mutate: func(c *Config) {
				c.Mode = "production"
				c.Server.Endpoints["token_api"] = cfgloader.EndpointConfig{
					Listen: "localhost:8081",
					Auth:   cfgloader.AuthSettings{Type: "none"},
				}
			},
			wantErr:     true,
			errContains: "auth.type \"none\" for endpoint \"token_api\" is not allowed in production mode",
		},
		{
			name: "production mode rejects insecure non-loopback",
			mutate: func(c *Config) {
				c.Mode = "production"
				c.Server.Endpoints["token_api"] = cfgloader.EndpointConfig{
					Listen: "0.0.0.0:8081",
					Auth:   cfgloader.AuthSettings{Type: "bearer"},
				}
			},
			wantErr:     true,
			errContains: "TLS is required for non-loopback endpoint \"token_api\" in production mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			tt.mutate(&cfg)
			_, err := cfg.Validate(nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("Validate() error = %v, want error containing %q", err, tt.errContains)
			}
		})
	}
}
