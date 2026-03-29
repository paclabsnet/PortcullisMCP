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

import "testing"

// validBaseConfig returns a minimal valid Config so individual tests can vary
// exactly one field at a time without triggering unrelated errors.
func validBaseConfig() Config {
	return Config{
		Keep: KeepConfig{Endpoint: "http://keep.example.com"},
	}
}

func TestConfig_Validate_KeepEndpointRequired(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Keep.Endpoint = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when keep.endpoint is empty")
	}
}

func TestConfig_Validate_IdentitySource(t *testing.T) {
	tests := []struct {
		source  string
		wantErr bool
	}{
		{"", false},
		{"os", false},
		{"oidc-file", true}, // token_file not set
		{"oidc-login", true}, // issuer_url not set
		{"ldap", true},
	}
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.Identity.Source = tc.source
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestConfig_Validate_OIDCFileTokenFileRequired(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Identity.Source = "oidc-file"
	cfg.Identity.OIDCFile.TokenFile = "/path/to/token"
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error with token_file set; got: %v", err)
	}
}

func TestConfig_Validate_OIDCLoginRequired(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Identity.Source = "oidc-login"
	cfg.Identity.OIDCLogin.IssuerURL = "https://idp.example.com"
	cfg.Identity.OIDCLogin.ClientID = "client-id"
	cfg.ManagementAPI.Port = 7777
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error with issuer_url, client_id, and mgmt port set; got: %v", err)
	}
}

func TestConfig_Validate_OIDCLoginRequiresManagementAPI(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Identity.Source = "oidc-login"
	cfg.Identity.OIDCLogin.IssuerURL = "https://idp.example.com"
	cfg.Identity.OIDCLogin.ClientID = "client-id"
	cfg.ManagementAPI.Port = 0 // Explicitly disabled
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when oidc-login is used but management_api.port is 0")
	}
}

func TestConfig_Validate_ApprovalManagementStrategy(t *testing.T) {
	tests := []struct {
		strategy string
		wantErr  bool
	}{
		{"", false},
		{"user-driven", false},
		{"proactive", false},
		{"Proactive", true},
		{"USER-DRIVEN", true},
		{"proactve", true}, // typo
		{"unknown", true},
	}
	for _, tc := range tests {
		t.Run(tc.strategy, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.Guard.ApprovalManagementStrategy = tc.strategy
			if tc.strategy == "proactive" {
				cfg.Guard.EscalationApprovalEndpoint = "http://guard.example.com"
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
	cfg.Guard.ApprovalManagementStrategy = "proactive"
	cfg.Guard.EscalationApprovalEndpoint = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when proactive strategy set but guard.escalation_approval_endpoint is empty")
	}
}
