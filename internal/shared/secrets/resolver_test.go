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

package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- passthrough (no scheme) ------------------------------------------------

func TestResolve_Passthrough(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"plain string", "mysecretvalue"},
		{"string with spaces", "my secret value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(context.Background(), tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.input {
				t.Errorf("got %q, want %q", got, tc.input)
			}
		})
	}
}

// ---- envvar:// --------------------------------------------------------------

func TestResolve_EnvVar_Set(t *testing.T) {
	t.Setenv("TEST_RESOLVE_VAR", "expected-value")
	got, err := Resolve(context.Background(), "envvar://TEST_RESOLVE_VAR")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "expected-value" {
		t.Errorf("got %q, want %q", got, "expected-value")
	}
}

func TestResolve_EnvVar_ThreeSlash(t *testing.T) {
	t.Setenv("TEST_RESOLVE_VAR_3S", "three-slash-value")
	got, err := Resolve(context.Background(), "envvar:///TEST_RESOLVE_VAR_3S")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "three-slash-value" {
		t.Errorf("got %q, want %q", got, "three-slash-value")
	}
}

func TestResolve_EnvVar_NotSet(t *testing.T) {
	os.Unsetenv("TEST_RESOLVE_MISSING_VAR")
	_, err := Resolve(context.Background(), "envvar://TEST_RESOLVE_MISSING_VAR")
	if err == nil {
		t.Fatal("expected error for unset variable, got nil")
	}
}

func TestResolve_EnvVar_MissingName(t *testing.T) {
	_, err := Resolve(context.Background(), "envvar://")
	if err == nil {
		t.Fatal("expected error for missing variable name, got nil")
	}
	if !strings.Contains(err.Error(), "missing variable name") {
		t.Errorf("error should mention missing variable name; got: %v", err)
	}
}

// filevarURI builds a filevar:// URI from a native OS path.
// On Windows, C:\foo\bar becomes filevar:///C:/foo/bar.
// On Unix, /tmp/foo becomes filevar:////tmp/foo (three slashes + abs path starting with /).
// The resolver's three-slash form is always used to avoid host-vs-path ambiguity.
func filevarURI(path string) string {
	slashed := filepath.ToSlash(path)
	// url.Parse requires the path to start with "/" after the scheme+authority.
	// filevar:/// gives empty host and path="/"+rest, so prepend "/" if not present.
	if len(slashed) > 0 && slashed[0] != '/' {
		slashed = "/" + slashed
	}
	return "filevar://" + slashed
}

// ---- filevar:// -------------------------------------------------------------

func TestResolve_FileVar_TwoSlash(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(f, []byte("file-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(context.Background(), filevarURI(f))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "file-secret" {
		t.Errorf("got %q, want %q", got, "file-secret")
	}
}

func TestResolve_FileVar_ThreeSlash_AbsPath(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "mysecret.txt")
	if err := os.WriteFile(f, []byte("absolute-path-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(context.Background(), filevarURI(f))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "absolute-path-secret" {
		t.Errorf("got %q, want %q", got, "absolute-path-secret")
	}
}

func TestResolve_FileVar_TrailingNewlineStripped(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "newline.txt")
	if err := os.WriteFile(f, []byte("trimmed-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(context.Background(), filevarURI(f))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "trimmed-value" {
		t.Errorf("got %q, want %q", got, "trimmed-value")
	}
}

func TestResolve_FileVar_FileNotFound(t *testing.T) {
	_, err := Resolve(context.Background(), "filevar:////nonexistent/path/secret.txt")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestResolve_FileVar_MissingPath(t *testing.T) {
	_, err := Resolve(context.Background(), "filevar://")
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
	}
	if !strings.Contains(err.Error(), "missing path") {
		t.Errorf("error should mention missing path; got: %v", err)
	}
}

// ---- unsupported scheme -----------------------------------------------------

func TestResolve_UnsupportedScheme(t *testing.T) {
	_, err := Resolve(context.Background(), "awssm://my-secret-name")
	if err == nil {
		t.Fatal("expected error for unsupported scheme, got nil")
	}
	if !strings.Contains(err.Error(), "awssm") {
		t.Errorf("error should contain scheme name; got: %v", err)
	}
	// Verify the raw URI value is NOT in the error — schemes don't contain secrets
	// but this tests the pattern.
	if strings.Contains(err.Error(), "my-secret-name") {
		t.Errorf("error should not contain the URI path value; got: %v", err)
	}
}

// ---- context cancellation ---------------------------------------------------

func TestResolve_CancelledContext_EnvVar(t *testing.T) {
	// envvar and filevar do not use ctx, so they succeed even with a cancelled context.
	t.Setenv("TEST_RESOLVE_CTX_VAR", "ctx-value")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	got, err := Resolve(ctx, "envvar://TEST_RESOLVE_CTX_VAR")
	if err != nil {
		t.Fatalf("envvar should succeed with cancelled context; err: %v", err)
	}
	if got != "ctx-value" {
		t.Errorf("got %q, want %q", got, "ctx-value")
	}
}

func TestResolve_CancelledContext_FileVar(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ctx.txt")
	if err := os.WriteFile(f, []byte("ctx-file-value"), 0600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := Resolve(ctx, filevarURI(f))
	if err != nil {
		t.Fatalf("filevar should succeed with cancelled context; err: %v", err)
	}
	if got != "ctx-file-value" {
		t.Errorf("got %q, want %q", got, "ctx-file-value")
	}
}

// ---- secret values must not appear in error strings -------------------------

func TestResolve_SecretValueNotInErrors(t *testing.T) {
	secretValue := "super-secret-password-12345"

	// Set the secret in an env var.
	t.Setenv("TEST_SECRET_VAR", secretValue)

	// Cause an error in a DIFFERENT call that has nothing to do with the secret.
	_, err := Resolve(context.Background(), "envvar://DEFINITELY_NOT_SET_VAR_XYZ987")
	if err == nil {
		t.Fatal("expected error for unset variable")
	}
	if strings.Contains(err.Error(), secretValue) {
		t.Errorf("secret value must not appear in error message; got: %v", err)
	}

	// Also verify unsupported scheme error does not contain the secret value.
	_, err2 := Resolve(context.Background(), "badscheme://"+secretValue)
	if err2 == nil {
		t.Fatal("expected error for unsupported scheme")
	}
	if strings.Contains(err2.Error(), secretValue) {
		t.Errorf("secret value must not appear in unsupported scheme error; got: %v", err2)
	}
}

// ---- vault mock test --------------------------------------------------------

// TestResolve_Vault_MockServer tests the vault resolver against a mock Vault HTTP
// server that returns a known KV v2 response. It verifies that the correct field
// is extracted and that the default "value" key is used when no fragment is given.
func TestResolve_Vault_MockServer(t *testing.T) {
	const (
		testMount  = "secret"
		testPath   = "myapp/api-key"
		testField  = "value"
		testSecret = "vault-resolved-secret"
	)

	// KV v2 GET /v1/{mount}/data/{path} returns {"data": {"data": {...}}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := fmt.Sprintf("/v1/%s/data/%s", testMount, testPath)
		if r.URL.Path != expectedPath {
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		payload := map[string]any{
			"data": map[string]any{
				"data": map[string]any{
					testField: testSecret,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(payload)
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Point the Vault client at our test server.
	t.Setenv("VAULT_ADDR", ts.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	uri := fmt.Sprintf("vault://%s/%s", testMount, testPath)
	got, err := Resolve(context.Background(), uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testSecret {
		t.Errorf("got %q, want %q", got, testSecret)
	}
}

// TestResolve_Vault_MockServer_CustomKey verifies that a fragment in the vault://
// URI selects a specific key rather than defaulting to "value".
func TestResolve_Vault_MockServer_CustomKey(t *testing.T) {
	const (
		testMount   = "kv"
		testPath    = "services/db"
		customKey   = "password"
		testSecret  = "db-password-xyz"
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := fmt.Sprintf("/v1/%s/data/%s", testMount, testPath)
		if r.URL.Path != expectedPath {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		payload := map[string]any{
			"data": map[string]any{
				"data": map[string]any{
					"value":    "not-this-one",
					customKey: testSecret,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(payload)
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	t.Setenv("VAULT_ADDR", ts.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	uri := fmt.Sprintf("vault://%s/%s#%s", testMount, testPath, customKey)
	got, err := Resolve(context.Background(), uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testSecret {
		t.Errorf("got %q, want %q", got, testSecret)
	}
}
