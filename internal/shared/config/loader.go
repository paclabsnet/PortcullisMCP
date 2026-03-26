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

// Package config provides a generic YAML config loader shared by all
// PortcullisMCP services. It handles:
//
//  1. ~ expansion in file paths
//  2. Strict YAML unmarshaling (unknown fields are rejected)
//  3. Secret URI resolution via internal/shared/secrets
//  4. Config validation via the Loadable.Validate() method
//
// Usage:
//
//	cfg, err := config.Load[keep.Config](ctx, path, keep.SecretAllowlist)
package config

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/paclabsnet/PortcullisMCP/internal/shared/secrets"
)

// Loadable is the constraint for config types supported by Load.
// Any struct with a Validate() method satisfies this interface.
type Loadable interface {
	Validate() error
}

// Load reads a YAML config file from path, strict-unmarshals it into T,
// resolves all secret URIs against allowlist, then validates the result.
//
// The allowlist controls which config fields may use vault:// and other
// restricted secret URI schemes; see internal/shared/secrets for details.
// ~ at the start of path is expanded to the current user's home directory.
func Load[T Loadable](ctx context.Context, path string, allowlist []string) (T, error) {
	var zero T

	expanded, err := expandHome(path)
	if err != nil {
		return zero, fmt.Errorf("expand config path: %w", err)
	}

	data, err := os.ReadFile(expanded)
	if err != nil {
		return zero, err
	}

	var cfg T
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return zero, err
	}

	if err := secrets.ResolveConfig(ctx, &cfg, allowlist); err != nil {
		return zero, fmt.Errorf("resolve secrets: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return zero, err
	}

	return cfg, nil
}

// expandHome replaces a leading ~ with the current user's home directory.
func expandHome(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return home + path[1:], nil
}
