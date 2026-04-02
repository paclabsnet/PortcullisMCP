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

package config

import "github.com/paclabsnet/PortcullisMCP/internal/shared/tlsutil"

// PeerAuth defines how one Portcullis service authenticates to another.
type PeerAuth struct {
	Type        string          `yaml:"type"` // "none", "bearer", "mtls"
	Credentials AuthCredentials `yaml:"credentials"`
}

// AuthCredentials holds the secrets used for peer-to-peer authentication.
type AuthCredentials struct {
	BearerToken string `yaml:"bearer_token"`
	Cert        string `yaml:"cert"`
	Key         string `yaml:"key"`
	ServerCA    string `yaml:"server_ca"`
}

// ServerConfig defines the listening endpoints and their security settings.
type ServerConfig struct {
	Endpoints map[string]EndpointConfig `yaml:"endpoints"`
}

// EndpointConfig defines a single listening port and its auth requirements.
type EndpointConfig struct {
	Listen string            `yaml:"listen"`
	TLS    tlsutil.TLSConfig `yaml:"tls"`
	Auth   PeerAuth          `yaml:"auth"`
}

// IdentityConfig defines the source of user identity for the component.
type IdentityConfig struct {
	Source string                 `yaml:"source"`
	Config map[string]interface{} `yaml:"config"`
}

// OperationsConfig holds the "run-the-service" settings like logging and telemetry.
type OperationsConfig struct {
	Storage   StorageConfig   `yaml:"storage"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
	Logging   LoggingConfig   `yaml:"logging"`
	Limits    LimitsConfig    `yaml:"limits"`
}

// StorageConfig defines the backend storage settings.
type StorageConfig struct {
	Backend string                 `yaml:"backend"`
	Config  map[string]interface{} `yaml:"config"`
}

// TelemetryConfig defines OpenTelemetry settings.
type TelemetryConfig struct {
	Exporter    string     `yaml:"exporter"`
	ServiceName string     `yaml:"service_name"`
	OTLP        OTLPConfig `yaml:"otlp"`
}

// OTLPConfig defines OTLP exporter settings.
type OTLPConfig struct {
	Endpoint string            `yaml:"endpoint"`
	Headers  map[string]string `yaml:"headers"`
}

// LoggingConfig defines structured logging settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// LimitsConfig defines rate limits and concurrency controls.
type LimitsConfig struct {
	Rate   LimitsRateConfig   `yaml:"rate"`
	Global LimitsGlobalConfig `yaml:"global"`
}

// LimitsRateConfig defines request rate limits.
type LimitsRateConfig struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

// LimitsGlobalConfig defines global service limits.
type LimitsGlobalConfig struct {
	MaxConcurrentRequests int `yaml:"max_concurrent_requests"`
}
