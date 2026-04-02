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
)

func validGuardConfig() Config {
	return Config{
		Listen: ListenConfig{
			UIAddress:  ":8444",
			APIAddress: ":8445",
		},
		Keep:                   KeepConfig{PendingEscalationRequestSigningKey: "keep-key-32bytes!!!!!!!!!!!!!!!"},
		EscalationTokenSigning: SigningConfig{Key: "signing-key-32bytes!!!!!!!!!!!!!"},
		Auth:                   AuthConfig{BearerToken: "test-token"},
	}
}

func TestGuardConfig_Validate_Valid(t *testing.T) {
	if err := validGuardConfig().Validate(); err != nil {
		t.Errorf("expected valid config to pass; got: %v", err)
	}
}

func TestGuardConfig_Validate_UIAddressRequired(t *testing.T) {
	cfg := validGuardConfig()
	cfg.Listen.UIAddress = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when listen.ui_address is empty")
	}
}

func TestGuardConfig_Validate_APIAddressRequired(t *testing.T) {
	cfg := validGuardConfig()
	cfg.Listen.APIAddress = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when listen.api_address is empty")
	}
}

func TestGuardConfig_Validate_KeepKeyRequired(t *testing.T) {
	cfg := validGuardConfig()
	cfg.Keep.PendingEscalationRequestSigningKey = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when keep.escalation_request_signing_key is empty")
	}
}

func TestGuardConfig_Validate_SigningKeyRequired(t *testing.T) {
	cfg := validGuardConfig()
	cfg.EscalationTokenSigning.Key = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when escalation_token_signing.key is empty")
	}
}

func TestGuardConfig_Validate_NoAuthToken_NoFlag_Error(t *testing.T) {
	cfg := validGuardConfig()
	cfg.Auth = AuthConfig{} // no bearer token, no mtls, no flag
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when bearer_token and mtls.client_ca are empty and allow_unauthenticated is false")
	}
	if !strings.Contains(err.Error(), "bearer_token") {
		t.Errorf("error should mention bearer_token; got: %v", err)
	}
}

func TestGuardConfig_Validate_NoAuthToken_WithFlag_OK(t *testing.T) {
	cfg := validGuardConfig()
	cfg.Auth = AuthConfig{AllowUnauthenticated: true}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error when allow_unauthenticated is true; got: %v", err)
	}
}

func TestGuardConfig_Validate_MtlsClientCA_NoBearer_OK(t *testing.T) {
	cfg := validGuardConfig()
	cfg.Auth = AuthConfig{Mtls: MtlsConfig{ClientCA: "/tls/ca.crt"}}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error when mtls.client_ca is set without bearer_token; got: %v", err)
	}
}
