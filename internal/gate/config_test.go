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
	"testing"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// validBaseConfig returns a minimal valid Config so individual tests can vary
// exactly one field at a time without triggering unrelated errors.
func validBaseConfig() Config {
	return Config{
		Peers: PeersConfig{
			Keep: cfgloader.PeerAuth{Endpoint: "http://keep.example.com"},
		},
	}
}

func TestConfig_Validate_KeepEndpointRequired(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Peers.Keep.Endpoint = ""
	if err := cfg.Validate(); err == nil {
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
			err := cfg.Validate()
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
	if err := cfg.Validate(); err != nil {
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
	if err := cfg.Validate(); err != nil {
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
			err := cfg.Validate()
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
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when proactive strategy set but peers.guard.endpoints.approval_ui is empty")
	}
}

