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

import "fmt"

// Validate returns an error if the configuration contains invalid values.
func (c Config) Validate() error {
	if c.Listen.Address == "" {
		return fmt.Errorf("listen.address is required")
	}
	if c.Keep.EscalationRequestSigningKey == "" {
		return fmt.Errorf("keep.escalation_request_signing_key is required")
	}
	if c.EscalationTokenSigning.Key == "" {
		return fmt.Errorf("escalation_token_signing.key is required")
	}
	return nil
}

// Config holds the full portcullis-guard configuration.
type Config struct {
	Listen                  ListenConfig    `yaml:"listen"`
	Keep                    KeepConfig      `yaml:"keep"`
	EscalationTokenSigning  SigningConfig   `yaml:"escalation_token_signing"`
	Templates               TemplatesConfig `yaml:"templates"`
	PortcullisGateManagementPort int          `yaml:"portcullis_gate_management_port"` // gate management API port shown in post-approval instructions (default: 7777)
	Auth                    AuthConfig      `yaml:"auth"`
	TokenStore              TokenStoreConfig `yaml:"token_store"`
}

// AuthConfig controls authentication for the token API endpoints.
// /token/unclaimed/list and /token/deposit require a valid bearer token.
// /token/claim does not require auth — the JTI is treated as a capability.
type AuthConfig struct {
	BearerToken string `yaml:"bearer_token"`
}

// TokenStoreConfig controls the in-memory unclaimed token store.
type TokenStoreConfig struct {
	// TTL is the default lifetime (in seconds) for unclaimed tokens when no
	// expiry can be parsed from the token itself (default: 3600 = 1 hour).
	TTL int `yaml:"ttl"`
	// CleanupInterval is how often (in seconds) Guard scans for and removes
	// expired unclaimed tokens (default: 300 = 5 minutes).
	CleanupInterval int `yaml:"cleanup_interval"`
}

type ListenConfig struct {
	Address string `yaml:"address"`
}

// KeepConfig holds the key Guard uses to verify Keep-signed escalation request JWTs.
type KeepConfig struct {
	EscalationRequestSigningKey string `yaml:"escalation_request_signing_key"` // must match keep.signing.key
}

// SigningConfig holds the key Guard uses to sign escalation token JWTs.
// The PDP must be configured to trust tokens signed with this key.
type SigningConfig struct {
	Key string `yaml:"key"` // HMAC secret; reference env var with ${VAR}
	TTL int    `yaml:"ttl"` // escalation token TTL in seconds (default: 86400 = 24h)
}

// TemplatesConfig points to the directory containing approval.html and token.html.
// If Dir is empty, Guard uses its built-in default templates from the installation.
type TemplatesConfig struct {
	Dir string `yaml:"dir"`
}
