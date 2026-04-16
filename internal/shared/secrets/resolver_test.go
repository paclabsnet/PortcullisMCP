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
	"reflect"
	"strings"
	"testing"
)

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

// wrapField is a helper that puts a single string value into a struct so
// ResolveConfig can be used in tests that only care about a single string.
func wrapResolve(ctx context.Context, raw string, allowlist []string) (string, error) {
	s := &struct {
		Val string `yaml:"val"`
	}{Val: raw}
	if _, err := ResolveConfig(ctx, s, allowlist); err != nil {
		return "", err
	}
	return s.Val, nil
}

// ---- passthrough (no scheme) ------------------------------------------------

func TestResolveConfig_Passthrough(t *testing.T) {
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
			got, err := wrapResolve(context.Background(), tc.input, nil)
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

func TestResolveConfig_EnvVar_Set(t *testing.T) {
	t.Setenv("TEST_RESOLVE_VAR", "expected-value")
	got, err := wrapResolve(context.Background(), "envvar://TEST_RESOLVE_VAR", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "expected-value" {
		t.Errorf("got %q, want %q", got, "expected-value")
	}
}

func TestResolveConfig_EnvVar_ThreeSlash(t *testing.T) {
	t.Setenv("TEST_RESOLVE_VAR_3S", "three-slash-value")
	got, err := wrapResolve(context.Background(), "envvar:///TEST_RESOLVE_VAR_3S", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "three-slash-value" {
		t.Errorf("got %q, want %q", got, "three-slash-value")
	}
}

func TestResolveConfig_EnvVar_NotSet(t *testing.T) {
	os.Unsetenv("TEST_RESOLVE_MISSING_VAR")
	_, err := wrapResolve(context.Background(), "envvar://TEST_RESOLVE_MISSING_VAR", nil)
	if err == nil {
		t.Fatal("expected error for unset variable, got nil")
	}
}

func TestResolveConfig_EnvVar_MissingName(t *testing.T) {
	_, err := wrapResolve(context.Background(), "envvar://", nil)
	if err == nil {
		t.Fatal("expected error for missing variable name, got nil")
	}
	if !strings.Contains(err.Error(), "missing variable name") {
		t.Errorf("error should mention missing variable name; got: %v", err)
	}
}

// ---- filevar:// -------------------------------------------------------------

func TestResolveConfig_FileVar_TwoSlash(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(f, []byte("file-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	// Three-slash form: filevar:///abs/path
	threeSlash, err := wrapResolve(context.Background(), filevarURI(f), nil)
	if err != nil {
		t.Fatalf("three-slash unexpected error: %v", err)
	}
	// Two-slash form: filevar://abs/path — url.Parse puts first path segment
	// into Host. Both forms must resolve to the same absolute path.
	slashed := strings.TrimPrefix(filepath.ToSlash(f), "/")
	twoSlashURI := "filevar://" + slashed
	twoSlash, err := wrapResolve(context.Background(), twoSlashURI, nil)
	if err != nil {
		t.Fatalf("two-slash unexpected error: %v", err)
	}
	if threeSlash != twoSlash {
		t.Errorf("two-slash %q resolved to %q, three-slash resolved to %q — must be equal",
			twoSlashURI, twoSlash, threeSlash)
	}
	if twoSlash != "file-secret" {
		t.Errorf("got %q, want %q", twoSlash, "file-secret")
	}
}

func TestResolveConfig_FileVar_ThreeSlash_AbsPath(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "mysecret.txt")
	if err := os.WriteFile(f, []byte("absolute-path-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := wrapResolve(context.Background(), filevarURI(f), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "absolute-path-secret" {
		t.Errorf("got %q, want %q", got, "absolute-path-secret")
	}
}

func TestResolveConfig_FileVar_TrailingNewlineStripped(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "newline.txt")
	if err := os.WriteFile(f, []byte("trimmed-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := wrapResolve(context.Background(), filevarURI(f), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "trimmed-value" {
		t.Errorf("got %q, want %q", got, "trimmed-value")
	}
}

func TestResolveConfig_FileVar_FileNotFound(t *testing.T) {
	_, err := wrapResolve(context.Background(), "filevar:////nonexistent/path/secret.txt", nil)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), "cannot read secret file") {
		t.Errorf("error should mention cannot read secret file; got: %v", err)
	}
}

func TestResolveConfig_FileVar_MissingPath(t *testing.T) {
	_, err := wrapResolve(context.Background(), "filevar://", nil)
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
	}
	if !strings.Contains(err.Error(), "missing path") {
		t.Errorf("error should mention missing path; got: %v", err)
	}
}

// ---- unrecognised scheme passthrough ----------------------------------------

func TestResolveConfig_UnrecognisedScheme_PassedThrough(t *testing.T) {
	// Schemes that are not secret URI schemes (http, https, ftp, etc.) must be
	// left unchanged — they are legitimate config values such as endpoint URLs.
	cases := []string{
		"http://keep.internal:8080",
		"https://guard.example.com/api",
		"ftp://files.example.com/data",
		"awssm://my-secret-name", // looks like a secret but not in restrictedSchemes
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			got, err := wrapResolve(context.Background(), raw, nil)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", raw, err)
			}
			if got != raw {
				t.Errorf("got %q, want unchanged %q", got, raw)
			}
		})
	}
}

// ---- restricted scheme on non-allowlisted field ----------------------------

func TestResolveConfig_RestrictedScheme_NonAllowlisted_Error(t *testing.T) {
	// vault:// (a restricted scheme) on a non-allowlisted field must produce
	// a clear "not permitted" error naming the field and the scheme.
	_, err := wrapResolve(context.Background(), "vault://secret/portcullis#key", nil)
	if err == nil {
		t.Fatal("expected error for vault:// on non-allowlisted field, got nil")
	}
	if !strings.Contains(err.Error(), "vault") {
		t.Errorf("error should contain scheme name; got: %v", err)
	}
	if !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("error should say 'not permitted'; got: %v", err)
	}
}

// ---- restricted schemes: vault, awssec, gcpsec, azkv ----------------------

func TestResolveConfig_Vault_NonAllowlisted(t *testing.T) {
	// vault:// on a field that is NOT in the allowlist must be refused.
	_, err := wrapResolve(context.Background(), "vault://secret/testpath#mykey", nil)
	if err == nil {
		t.Fatal("expected error for vault:// on non-allowlisted field, got nil")
	}
	if !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("error should mention 'not permitted'; got: %v", err)
	}
	if !strings.Contains(err.Error(), "val") {
		t.Errorf("error should contain the field path; got: %v", err)
	}
}

func TestResolveConfig_AwsSec_NonAllowlisted(t *testing.T) {
	_, err := wrapResolve(context.Background(), "awssec://my/secret", nil)
	if err == nil {
		t.Fatal("expected error for awssec:// on non-allowlisted field, got nil")
	}
	if !strings.Contains(err.Error(), "not permitted") {
		t.Errorf("error should mention 'not permitted'; got: %v", err)
	}
}

func TestResolveConfig_AwsSec_Allowlisted(t *testing.T) {
	// awssec is in restrictedSchemes but resolveRestricted only handles vault.
	// When the field is allowlisted the call reaches resolveRestricted which
	// returns "not yet implemented" for non-vault schemes.
	_, err := wrapResolve(context.Background(), "awssec://my/secret", []string{"val"})
	if err == nil {
		t.Fatal("expected error for unimplemented awssec://, got nil")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("error should mention 'not yet implemented'; got: %v", err)
	}
}

// ---- vault mock test --------------------------------------------------------

func TestResolveConfig_Vault_MockServer(t *testing.T) {
	const (
		testMount  = "secret"
		testPath   = "testpath"
		testKey    = "mykey"
		testSecret = "mysecretvalue"
	)

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
					testKey: testSecret,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(payload)
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	t.Setenv("VAULT_ADDR", ts.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	uri := fmt.Sprintf("vault://%s/%s#%s", testMount, testPath, testKey)
	got, err := wrapResolve(context.Background(), uri, []string{"val"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testSecret {
		t.Errorf("got %q, want %q", got, testSecret)
	}
}

func TestResolveConfig_Vault_MockServer_DefaultKey(t *testing.T) {
	const (
		testMount  = "secret"
		testPath   = "myapp/api-key"
		testSecret = "vault-resolved-secret"
	)

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
					"value": testSecret,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(payload)
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	t.Setenv("VAULT_ADDR", ts.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	uri := fmt.Sprintf("vault://%s/%s", testMount, testPath)
	got, err := wrapResolve(context.Background(), uri, []string{"val"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testSecret {
		t.Errorf("got %q, want %q", got, testSecret)
	}
}

func TestResolveConfig_Vault_MockServer_CustomKey(t *testing.T) {
	const (
		testMount  = "kv"
		testPath   = "services/db"
		customKey  = "password"
		testSecret = "db-password-xyz"
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
					"value":   "not-this-one",
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
	got, err := wrapResolve(context.Background(), uri, []string{"val"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testSecret {
		t.Errorf("got %q, want %q", got, testSecret)
	}
}

func TestResolveConfig_Vault_MockServer_Errors(t *testing.T) {
	t.Run("read failure", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "vault down", http.StatusInternalServerError)
		})
		ts := httptest.NewServer(handler)
		defer ts.Close()
		t.Setenv("VAULT_ADDR", ts.URL)
		t.Setenv("VAULT_TOKEN", "test")

		_, err := wrapResolve(context.Background(), "vault://s/p#k", []string{"val"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "vault read failed") {
			t.Errorf("wrong error: %v", err)
		}
	})

	t.Run("no data", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": nil})
		})
		ts := httptest.NewServer(handler)
		defer ts.Close()
		t.Setenv("VAULT_ADDR", ts.URL)
		t.Setenv("VAULT_TOKEN", "test")

		_, err := wrapResolve(context.Background(), "vault://s/p#k", []string{"val"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "vault returned no data") {
			t.Errorf("wrong error: %v", err)
		}
	})

	t.Run("key not found", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			payload := map[string]any{
				"data": map[string]any{
					"data": map[string]any{"other": "val"},
				},
			}
			_ = json.NewEncoder(w).Encode(payload)
		})
		ts := httptest.NewServer(handler)
		defer ts.Close()
		t.Setenv("VAULT_ADDR", ts.URL)
		t.Setenv("VAULT_TOKEN", "test")

		_, err := wrapResolve(context.Background(), "vault://s/p#missing", []string{"val"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "not found in vault secret") {
			t.Errorf("wrong error: %v", err)
		}
	})

	t.Run("not a string", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			payload := map[string]any{
				"data": map[string]any{
					"data": map[string]any{"key": 123},
				},
			}
			_ = json.NewEncoder(w).Encode(payload)
		})
		ts := httptest.NewServer(handler)
		defer ts.Close()
		t.Setenv("VAULT_ADDR", ts.URL)
		t.Setenv("VAULT_TOKEN", "test")

		_, err := wrapResolve(context.Background(), "vault://s/p#key", []string{"val"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "is not a string") {
			t.Errorf("wrong error: %v", err)
		}
	})

	t.Run("missing mount", func(t *testing.T) {
		_, err := wrapResolve(context.Background(), "vault:///path", []string{"val"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing mount") {
			t.Errorf("wrong error: %v", err)
		}
	})

	t.Run("missing path", func(t *testing.T) {
		_, err := wrapResolve(context.Background(), "vault://mount", []string{"val"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing secret path") {
			t.Errorf("wrong error: %v", err)
		}
	})
}

// ---- context cancellation ---------------------------------------------------

func TestResolveConfig_CancelledContext_EnvVar(t *testing.T) {
	// envvar and filevar do not use ctx, so they succeed even with a cancelled context.
	t.Setenv("TEST_RESOLVE_CTX_VAR", "ctx-value")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	got, err := wrapResolve(ctx, "envvar://TEST_RESOLVE_CTX_VAR", nil)
	if err != nil {
		t.Fatalf("envvar should succeed with cancelled context; err: %v", err)
	}
	if got != "ctx-value" {
		t.Errorf("got %q, want %q", got, "ctx-value")
	}
}

func TestResolveConfig_CancelledContext_FileVar(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ctx.txt")
	if err := os.WriteFile(f, []byte("ctx-file-value"), 0600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := wrapResolve(ctx, filevarURI(f), nil)
	if err != nil {
		t.Fatalf("filevar should succeed with cancelled context; err: %v", err)
	}
	if got != "ctx-file-value" {
		t.Errorf("got %q, want %q", got, "ctx-file-value")
	}
}

func TestResolveConfig_CancelledContext_Vault(t *testing.T) {
	// With a cancelled context, the vault HTTP call should observe the
	// cancellation. The mock server is reachable but the context is pre-cancelled.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the request context was cancelled.
		select {
		case <-r.Context().Done():
			http.Error(w, "context cancelled", http.StatusServiceUnavailable)
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data": map[string]any{"value": "should-not-reach"},
				},
			})
		}
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	t.Setenv("VAULT_ADDR", ts.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := wrapResolve(ctx, "vault://secret/mypath#value", []string{"val"})
	// We expect an error because either the context cancelled the HTTP call or
	// the server returned an error response. Either way, success is wrong.
	if err == nil {
		t.Fatal("expected error with cancelled context for vault://, got nil")
	}
}

// ---- secret values must not appear in error strings -------------------------

func TestResolveConfig_SecretValueNotInErrors(t *testing.T) {
	secretValue := "super-secret-password-12345"

	// Set the secret in an env var.
	t.Setenv("TEST_SECRET_VAR", secretValue)

	// Cause an error in a DIFFERENT call that has nothing to do with the secret.
	_, err := wrapResolve(context.Background(), "envvar://DEFINITELY_NOT_SET_VAR_XYZ987", nil)
	if err == nil {
		t.Fatal("expected error for unset variable")
	}
	if strings.Contains(err.Error(), secretValue) {
		t.Errorf("secret value must not appear in error message; got: %v", err)
	}

	// Also verify that a restricted-scheme error on a non-allowlisted field
	// does not leak the secret value (the URI path is part of the raw string).
	_, err2 := wrapResolve(context.Background(), "vault://secret/"+secretValue+"#key", nil)
	if err2 == nil {
		t.Fatal("expected error for vault:// on non-allowlisted field")
	}
	if strings.Contains(err2.Error(), secretValue) {
		t.Errorf("secret value must not appear in restricted-scheme error; got: %v", err2)
	}
}

// ---- nested struct fields ---------------------------------------------------

func TestResolveConfig_NestedStruct(t *testing.T) {
	t.Setenv("NESTED_TEST_VAR", "nested-resolved")

	type Inner struct {
		Field string `yaml:"field"`
	}
	type Outer struct {
		Inner Inner `yaml:"inner"`
	}

	cfg := &Outer{
		Inner: Inner{Field: "envvar://NESTED_TEST_VAR"},
	}
	if _, err := ResolveConfig(context.Background(), cfg, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Inner.Field != "nested-resolved" {
		t.Errorf("got %q, want %q", cfg.Inner.Field, "nested-resolved")
	}
}

// ---- map[string]string values -----------------------------------------------

func TestResolveConfig_MapStringString(t *testing.T) {
	t.Setenv("MAP_SECRET_VAR", "map-resolved-value")

	type Cfg struct {
		Env map[string]string `yaml:"env"`
	}

	cfg := &Cfg{
		Env: map[string]string{
			"MY_KEY": "envvar://MAP_SECRET_VAR",
			"PLAIN":  "plain-value",
		},
	}
	if _, err := ResolveConfig(context.Background(), cfg, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Env["MY_KEY"] != "map-resolved-value" {
		t.Errorf("got %q, want %q", cfg.Env["MY_KEY"], "map-resolved-value")
	}
	if cfg.Env["PLAIN"] != "plain-value" {
		t.Errorf("got %q, want %q", cfg.Env["PLAIN"], "plain-value")
	}
}

// ---- map[string]struct values -----------------------------------------------

func TestResolveConfig_MapStringStruct(t *testing.T) {
	t.Setenv("STRUCT_MAP_VAR", "struct-map-resolved")

	type BackendCfg struct {
		Token string `yaml:"token"`
	}
	type Cfg struct {
		Backends map[string]BackendCfg `yaml:"backends"`
	}

	cfg := &Cfg{
		Backends: map[string]BackendCfg{
			"mybackend": {Token: "envvar://STRUCT_MAP_VAR"},
		},
	}
	if _, err := ResolveConfig(context.Background(), cfg, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Backends["mybackend"].Token != "struct-map-resolved" {
		t.Errorf("got %q, want %q", cfg.Backends["mybackend"].Token, "struct-map-resolved")
	}
}

// ---- non-pointer input ------------------------------------------------------

func TestResolveConfig_NonPointer(t *testing.T) {
	type Cfg struct {
		Val string `yaml:"val"`
	}
	_, err := ResolveConfig(context.Background(), Cfg{Val: "test"}, nil)
	if err == nil {
		t.Fatal("expected error for non-pointer input, got nil")
	}
	if !strings.Contains(err.Error(), "non-nil pointer") {
		t.Errorf("error should mention non-nil pointer; got: %v", err)
	}
}

// ---- yamlFieldName ----------------------------------------------------------

func TestYamlFieldName(t *testing.T) {
	type S struct {
		NoTag        string
		WithTag      string `yaml:"with_tag"`
		WithOmit     string `yaml:"with_omit,omitempty"`
		DashTag      string `yaml:"-"`
		EmptyNameTag string `yaml:",omitempty"`
	}
	rt := reflect.TypeOf(S{})
	cases := []struct {
		field string
		want  string
	}{
		{"NoTag", "NoTag"},
		{"WithTag", "with_tag"},
		{"WithOmit", "with_omit"},
		{"DashTag", "DashTag"},
		{"EmptyNameTag", "EmptyNameTag"},
	}
	for _, tc := range cases {
		f, _ := rt.FieldByName(tc.field)
		got := yamlFieldName(f)
		if got != tc.want {
			t.Errorf("yamlFieldName(%q) = %q, want %q", tc.field, got, tc.want)
		}
	}
}

// ---- slice elements ---------------------------------------------------------

func TestResolveConfig_SliceElements(t *testing.T) {
	t.Setenv("SLICE_VAR_0", "slice-value-0")
	t.Setenv("SLICE_VAR_1", "slice-value-1")

	type Cfg struct {
		Items []string `yaml:"items"`
	}
	cfg := &Cfg{
		Items: []string{"envvar://SLICE_VAR_0", "envvar://SLICE_VAR_1"},
	}
	if _, err := ResolveConfig(context.Background(), cfg, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Items[0] != "slice-value-0" {
		t.Errorf("items[0]: got %q, want %q", cfg.Items[0], "slice-value-0")
	}
	if cfg.Items[1] != "slice-value-1" {
		t.Errorf("items[1]: got %q, want %q", cfg.Items[1], "slice-value-1")
	}
}
