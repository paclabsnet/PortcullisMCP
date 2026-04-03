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

package config_test

import (
	"context"
	"os"
	"strings"
	"testing"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// testConfig is a minimal config struct used by loader tests.
type testConfig struct {
	Name    string `yaml:"name"`
	Secret  string `yaml:"secret"`
	BadFlag string `yaml:"bad_flag,omitempty"`
}

func (c testConfig) Validate(_ cfgloader.SourceMap) (cfgloader.PostureReport, error) {
	if c.Name == "" {
		return cfgloader.PostureReport{}, &validationError{"name is required"}
	}
	return cfgloader.PostureReport{}, nil
}

type validationError struct{ msg string }

func (e *validationError) Error() string { return e.msg }

// writeTemp writes content to a temp file and returns its path.
// The caller is responsible for removing the file.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "loader-test-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func TestLoad_ValidConfig(t *testing.T) {
	path := writeTemp(t, "name: test-service\n")
	cfg, _, err := cfgloader.Load[testConfig](context.Background(), path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Name != "test-service" {
		t.Errorf("Name = %q, want %q", cfg.Name, "test-service")
	}
}

func TestLoad_ValidationError(t *testing.T) {
	path := writeTemp(t, "secret: some-value\n") // name is missing
	_, _, err := cfgloader.Load[testConfig](context.Background(), path, nil)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "name is required") {
		t.Errorf("error should mention 'name is required'; got: %v", err)
	}
}

func TestLoad_UnknownFieldRejected(t *testing.T) {
	path := writeTemp(t, "name: svc\nunknown_field: oops\n")
	_, _, err := cfgloader.Load[testConfig](context.Background(), path, nil)
	if err == nil {
		t.Fatal("expected error for unknown YAML field, got nil")
	}
}

func TestLoad_EnvVarSecret(t *testing.T) {
	t.Setenv("TEST_LOADER_SECRET", "resolved-value")
	path := writeTemp(t, "name: svc\nsecret: envvar://TEST_LOADER_SECRET\n")
	cfg, _, err := cfgloader.Load[testConfig](context.Background(), path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Secret != "resolved-value" {
		t.Errorf("Secret = %q, want %q", cfg.Secret, "resolved-value")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, _, err := cfgloader.Load[testConfig](context.Background(), "/definitely/does/not/exist.yaml", nil)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoad_ResolverError_Wrapped(t *testing.T) {
	// vault:// on a non-allowlisted field should produce a "resolve secrets:" wrapped error.
	path := writeTemp(t, "name: svc\nsecret: vault://mymount/mypath#key\n")
	_, _, err := cfgloader.Load[testConfig](context.Background(), path, nil)
	if err == nil {
		t.Fatal("expected error for vault:// on non-allowlisted field, got nil")
	}
	if !strings.Contains(err.Error(), "resolve secrets:") {
		t.Errorf("error should be wrapped with 'resolve secrets:'; got: %v", err)
	}
}

func TestLoad_TildeExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}
	// Write a real file in a temp dir under home, then reference it with ~.
	dir, err := os.MkdirTemp(home, "loader-tilde-test-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)
	filePath := dir + "/config.yaml"
	if err := os.WriteFile(filePath, []byte("name: tilde-test\n"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Convert absolute path to tilde-relative.
	rel := "~" + strings.TrimPrefix(filePath, home)
	cfg, _, err := cfgloader.Load[testConfig](context.Background(), rel, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Name != "tilde-test" {
		t.Errorf("Name = %q, want %q", cfg.Name, "tilde-test")
	}
}
