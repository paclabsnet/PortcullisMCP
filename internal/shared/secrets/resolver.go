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

// Package secrets provides URI-based secret resolution for Portcullis
// configuration. Supported schemes:
//
//   - (no scheme)  — value returned as-is (sandbox/dev mode)
//   - envvar://    — resolved from an environment variable
//   - filevar://   — resolved from a local file (two or three slashes accepted)
//   - vault://     — resolved from HashiCorp Vault KV v2
//
// Vault resolver uses the standard environment variables VAULT_ADDR,
// VAULT_TOKEN, VAULT_NAMESPACE, and VAULT_CACERT. No Vault configuration
// is read from the Portcullis YAML files.
package secrets

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

// Resolve resolves a secret URI to its plaintext value.
// If the string contains no "://" it is returned unchanged (direct/passthrough mode).
// Secret values are never included in returned errors.
func Resolve(ctx context.Context, raw string) (string, error) {
	if !strings.Contains(raw, "://") {
		return raw, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("secrets: invalid URI: %w", err)
	}

	switch u.Scheme {
	case "envvar":
		return resolveEnvVar(u)
	case "filevar":
		return resolveFileVar(u)
	case "vault":
		return resolveVault(ctx, u)
	default:
		return "", fmt.Errorf("secrets: unsupported scheme %q", u.Scheme)
	}
}

// resolveEnvVar handles envvar://VAR_NAME
func resolveEnvVar(u *url.URL) (string, error) {
	// envvar://VAR_NAME  ->  host = "VAR_NAME", path = ""
	// envvar:///VAR_NAME ->  host = "",          path = "/VAR_NAME"
	name := u.Host
	if name == "" {
		name = strings.TrimPrefix(u.Path, "/")
	}
	if name == "" {
		return "", fmt.Errorf("secrets: envvar URI missing variable name")
	}
	val, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("secrets: environment variable %q is not set", name)
	}
	return val, nil
}

// resolveFileVar handles filevar:///path/to/file or filevar://path/to/file
func resolveFileVar(u *url.URL) (string, error) {
	// Normalize: strip one leading slash if host is empty (triple-slash form gives
	// empty host and path starting with "/"). Double-slash gives host as first
	// path segment — reconstruct the full path from host + path.
	var path string
	if u.Host != "" {
		// filevar://relative/path  — host holds first segment
		path = u.Host + u.Path
	} else {
		// filevar:///absolute/path — host empty, path starts with "/"
		path = u.Path
	}
	if path == "" {
		return "", fmt.Errorf("secrets: filevar URI missing path")
	}
	// On Windows, url.Parse leaves a leading "/" before the drive letter
	// (e.g. "/C:/foo/bar"). Strip it so os.ReadFile gets a valid Windows path.
	if len(path) >= 3 && path[0] == '/' && path[2] == ':' {
		path = path[1:]
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("secrets: cannot read secret file: %w", err)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

// resolveVault handles vault://[mount]/[path]#[key]
// The Vault KV v2 data/ prefix is automatically inserted by client.KVv2.
// If no fragment (key) is specified, the field "value" is used.
func resolveVault(ctx context.Context, u *url.URL) (string, error) {
	mount := u.Host
	if mount == "" {
		return "", fmt.Errorf("secrets: vault URI missing mount (e.g. vault://secret/path#key)")
	}
	secretPath := strings.TrimPrefix(u.Path, "/")
	if secretPath == "" {
		return "", fmt.Errorf("secrets: vault URI missing secret path")
	}
	key := u.Fragment
	if key == "" {
		key = "value"
	}

	cfg := vault.DefaultConfig()
	if err := cfg.ReadEnvironment(); err != nil {
		return "", fmt.Errorf("secrets: vault client config: %w", err)
	}
	client, err := vault.NewClient(cfg)
	if err != nil {
		return "", fmt.Errorf("secrets: vault client init: %w", err)
	}

	secret, err := client.KVv2(mount).Get(ctx, secretPath)
	if err != nil {
		return "", fmt.Errorf("secrets: vault read failed for path %q mount %q: %w", secretPath, mount, err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("secrets: vault returned no data for path %q mount %q", secretPath, mount)
	}
	raw, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("secrets: key %q not found in vault secret at path %q mount %q", key, secretPath, mount)
	}
	val, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("secrets: key %q in vault secret at path %q mount %q is not a string", key, secretPath, mount)
	}
	return val, nil
}
