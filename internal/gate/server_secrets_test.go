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
	"context"
	"os"
	"strings"
	"testing"

	"github.com/paclabsnet/PortcullisMCP/internal/shared/secrets"
)

// resolveGateConfig is a test helper that runs ResolveConfig over a gate.Config
// using the package-level allowlist, matching what gate.LoadConfig does at startup.
func resolveGateConfig(cfg *Config) error {
	return secrets.ResolveConfig(context.Background(), cfg, SecretAllowlist)
}

func TestGate_Secrets_EnvVar_AllowlistedField(t *testing.T) {
	t.Setenv("TEST_GATE_TOKEN", "resolved-bearer-token")
	cfg := validBaseConfig()
	cfg.Keep.Auth.Token = "envvar://TEST_GATE_TOKEN"

	if err := resolveGateConfig(&cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Keep.Auth.Token != "resolved-bearer-token" {
		t.Errorf("keep.auth.token = %q, want %q", cfg.Keep.Auth.Token, "resolved-bearer-token")
	}
}

func TestGate_Secrets_EnvVar_NonAllowlistedField(t *testing.T) {
	// envvar:// is unrestricted — resolves on any field including non-allowlisted ones.
	t.Setenv("TEST_GATE_ENDPOINT", "http://keep.internal:8080")
	cfg := validBaseConfig()
	cfg.Keep.Endpoint = "envvar://TEST_GATE_ENDPOINT"

	if err := resolveGateConfig(&cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Keep.Endpoint != "http://keep.internal:8080" {
		t.Errorf("keep.endpoint = %q, want %q", cfg.Keep.Endpoint, "http://keep.internal:8080")
	}
}

func TestGate_Secrets_Vault_NonAllowlistedField_Rejected(t *testing.T) {
	// vault:// on a non-allowlisted field must fail fast with a clear error.
	cfg := validBaseConfig()
	cfg.Keep.Endpoint = "vault://secret/portcullis#endpoint"

	err := resolveGateConfig(&cfg)
	if err == nil {
		t.Fatal("expected error for vault:// on non-allowlisted field, got nil")
	}
	if !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("error should mention 'not permitted'; got: %v", err)
	}
	if !strings.Contains(err.Error(), "keep.endpoint") {
		t.Errorf("error should name the offending field 'keep.endpoint'; got: %v", err)
	}
}

func TestGate_Secrets_Vault_AllowlistedField_AttemptedNotPermittedError(t *testing.T) {
	// vault:// on an allowlisted field passes the allowlist check and attempts
	// Vault resolution. With no Vault server available it returns a vault error,
	// not a "not permitted" error.
	cfg := validBaseConfig()
	cfg.Keep.Auth.Token = "vault://secret/portcullis/gate#token"

	err := resolveGateConfig(&cfg)
	if err == nil {
		t.Fatal("expected error (no vault server in test env), got nil")
	}
	if strings.Contains(err.Error(), "not permitted") {
		t.Errorf("allowlisted field should not produce 'not permitted' error; got: %v", err)
	}
}

func TestGate_Secrets_GuardBearerToken_Allowlisted(t *testing.T) {
	t.Setenv("TEST_GATE_GUARD_TOKEN", "guard-bearer-value")
	cfg := validBaseConfig()
	cfg.Guard.Auth.BearerToken = "envvar://TEST_GATE_GUARD_TOKEN"

	if err := resolveGateConfig(&cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Guard.Auth.BearerToken != "guard-bearer-value" {
		t.Errorf("guard.auth.bearer_token = %q, want %q", cfg.Guard.Auth.BearerToken, "guard-bearer-value")
	}
}

func TestGate_Secrets_MgmtSharedSecret_Allowlisted(t *testing.T) {
	t.Setenv("TEST_GATE_MGMT_SECRET", "mgmt-secret-value")
	cfg := validBaseConfig()
	cfg.ManagementAPI.SharedSecret = "envvar://TEST_GATE_MGMT_SECRET"

	if err := resolveGateConfig(&cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ManagementAPI.SharedSecret != "mgmt-secret-value" {
		t.Errorf("management_api.shared_secret = %q, want %q", cfg.ManagementAPI.SharedSecret, "mgmt-secret-value")
	}
}

func TestGate_Secrets_EnvVarNotSet_ReturnsError(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Keep.Auth.Token = "envvar://DEFINITELY_NOT_SET_GATE_VAR"

	err := resolveGateConfig(&cfg)
	if err == nil {
		t.Fatal("expected error for unset env var, got nil")
	}
	if !strings.Contains(err.Error(), "DEFINITELY_NOT_SET_GATE_VAR") {
		t.Errorf("error should name the missing variable; got: %v", err)
	}
}

func TestGate_LoadConfig_WrapsResolverError(t *testing.T) {
	// LoadConfig must wrap resolver errors with "resolve secrets:" so that
	// operators see a clear prefix in startup logs.
	// Use an allowlisted field (keep.auth.token) with a vault:// URI so the
	// allowlist check passes and the error comes from the Vault dial attempt.
	yaml := "keep:\n  endpoint: \"http://keep.example.com\"\n  auth:\n    type: bearer\n    token: \"vault://secret/portcullis/gate#token\"\n"
	f, err := os.CreateTemp("", "gate-config-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(yaml); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()

	_, err = LoadConfig(context.Background(), f.Name())
	if err == nil {
		t.Fatal("expected error from LoadConfig with unresolvable vault URI, got nil")
	}
	if !strings.Contains(err.Error(), "resolve secrets:") {
		t.Errorf("error should be wrapped with 'resolve secrets:'; got: %v", err)
	}
}

func TestGate_Secrets_Passthrough_Unchanged(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Keep.Auth.Token = "plain-literal-token"
	cfg.Guard.Auth.BearerToken = "another-literal"

	if err := resolveGateConfig(&cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Keep.Auth.Token != "plain-literal-token" {
		t.Errorf("plain token should be unchanged; got %q", cfg.Keep.Auth.Token)
	}
	if cfg.Guard.Auth.BearerToken != "another-literal" {
		t.Errorf("plain guard token should be unchanged; got %q", cfg.Guard.Auth.BearerToken)
	}
}
