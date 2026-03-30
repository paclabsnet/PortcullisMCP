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
		Listen:                 ListenConfig{Address: ":8444"},
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

func TestGuardConfig_Validate_ListenAddressRequired(t *testing.T) {
	cfg := validGuardConfig()
	cfg.Listen.Address = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error when listen.address is empty")
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
	cfg.Auth = AuthConfig{} // no bearer token, no flag
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when bearer_token is empty and allow_unauthenticated is false")
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
