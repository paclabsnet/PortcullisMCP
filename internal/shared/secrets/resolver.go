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
	"reflect"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

// restrictedSchemes are secret URI schemes that may only be used on allowlisted
// config fields. envvar:// and filevar:// are unrestricted and may appear anywhere.
var restrictedSchemes = map[string]bool{
	"vault":  true,
	"awssec": true,
	"gcpsec": true,
	"azkv":   true,
}

// ResolveConfig walks cfg (must be a non-nil pointer to a struct) using
// reflection and resolves every secret URI found in string fields.
//
// envvar:// and filevar:// are resolved on any field.
// vault:// (and future cloud schemes) are only resolved when the field's
// dotted YAML-tag path is present in allowlist; otherwise an error is returned.
//
// Field paths are built from yaml struct tag names (e.g. "listen.auth.bearer_token").
// If a field has no yaml tag the Go field name is used.
func ResolveConfig(ctx context.Context, cfg any, allowlist []string) error {
	allowset := make(map[string]bool, len(allowlist))
	for _, f := range allowlist {
		allowset[f] = true
	}
	v := reflect.ValueOf(cfg)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return fmt.Errorf("secrets: ResolveConfig requires a non-nil pointer")
	}
	return walkValue(ctx, v.Elem(), "", allowset)
}

func walkValue(ctx context.Context, v reflect.Value, path string, allowset map[string]bool) error {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return nil
		}
		return walkValue(ctx, v.Elem(), path, allowset)

	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := yamlFieldName(f)
			childPath := name
			if path != "" {
				childPath = path + "." + name
			}
			if err := walkValue(ctx, v.Field(i), childPath, allowset); err != nil {
				return err
			}
		}

	case reflect.String:
		if !v.CanSet() {
			return nil
		}
		resolved, err := resolve(ctx, v.String(), path, allowset)
		if err != nil {
			return err
		}
		v.SetString(resolved)

	case reflect.Map:
		for _, key := range v.MapKeys() {
			elem := v.MapIndex(key)
			childPath := fmt.Sprintf("%s.%v", path, key.Interface())
			if path == "" {
				childPath = fmt.Sprintf("%v", key.Interface())
			}
			switch elem.Kind() {
			case reflect.String:
				resolved, err := resolve(ctx, elem.String(), childPath, allowset)
				if err != nil {
					return err
				}
				v.SetMapIndex(key, reflect.ValueOf(resolved))
			case reflect.Struct, reflect.Ptr:
				// Map values are not addressable; copy into addressable memory.
				cp := reflect.New(elem.Type()).Elem()
				cp.Set(elem)
				if err := walkValue(ctx, cp, childPath, allowset); err != nil {
					return err
				}
				v.SetMapIndex(key, cp)
			}
		}

	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			childPath := fmt.Sprintf("%s[%d]", path, i)
			if err := walkValue(ctx, v.Index(i), childPath, allowset); err != nil {
				return err
			}
		}
	}
	return nil
}

// resolve resolves a single string value. path is used only for error messages.
func resolve(ctx context.Context, raw, path string, allowset map[string]bool) (string, error) {
	if !strings.Contains(raw, "://") {
		return raw, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("secrets: invalid URI at field %q: %w", path, err)
	}
	switch {
	case u.Scheme == "envvar":
		return resolveEnvVar(u)
	case u.Scheme == "filevar":
		return resolveFileVar(u)
	case restrictedSchemes[u.Scheme]:
		if !allowset[path] {
			return "", fmt.Errorf("secrets: %s:// URI is not permitted at field %q — only allowed on: %v",
				u.Scheme, path, allowlistKeys(allowset))
		}
		return resolveRestricted(ctx, u)
	default:
		return "", fmt.Errorf("secrets: unsupported scheme %q at field %q", u.Scheme, path)
	}
}

// resolveRestricted dispatches vault and future cloud scheme resolution.
func resolveRestricted(ctx context.Context, u *url.URL) (string, error) {
	switch u.Scheme {
	case "vault":
		return resolveVault(ctx, u)
	default:
		return "", fmt.Errorf("secrets: scheme %q is reserved for future use and not yet implemented", u.Scheme)
	}
}

// allowlistKeys returns field paths from the allowset for error messages.
func allowlistKeys(allowset map[string]bool) []string {
	keys := make([]string, 0, len(allowset))
	for k := range allowset {
		keys = append(keys, k)
	}
	return keys
}

// yamlFieldName returns the yaml tag name for a struct field, falling back to
// the Go field name. Tag options (e.g. ",omitempty") are stripped.
func yamlFieldName(f reflect.StructField) string {
	tag := f.Tag.Get("yaml")
	if tag == "" {
		return f.Name
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "" || name == "-" {
		return f.Name
	}
	return name
}

// resolveEnvVar handles envvar://VAR_NAME (two or three slashes).
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

// resolveFileVar handles filevar:///path/to/file or filevar://path/to/file.
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

// resolveVault handles vault://[mount]/[path]#[key].
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
