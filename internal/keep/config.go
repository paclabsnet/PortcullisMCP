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

package keep

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
	identity "github.com/paclabsnet/PortcullisMCP/internal/shared/identity"
)

// SecretAllowlist lists the config fields eligible for vault:// and other
// restricted secret URI schemes. envvar:// and filevar:// may be used on any field.
var SecretAllowlist = []string{
	"server.endpoints.main.tls.cert",
	"server.endpoints.main.tls.key",
	"server.endpoints.main.tls.client_ca",
	"server.endpoints.main.auth.credentials.bearer_token",
	"responsibility.issuance.signing_key",
	"responsibility.admin.token",
	"responsibility.workflow.config.headers",
	"responsibility.workflow.config.instance",
	"identity.config.secret",
	"peers.normalization.auth.credentials.bearer_token",
	"operations.storage.config.password",
}

// LoadConfig reads, parses, resolves secrets in, and validates a keep config file.
// It returns the config and a PostureReport for startup security attestation.
func LoadConfig(ctx context.Context, path string) (Config, cfgloader.PostureReport, error) {
	cfg, report, err := cfgloader.Load[*Config](ctx, path, SecretAllowlist)
	if err != nil {
		return Config{}, report, err
	}
	return *cfg, report, nil
}

// Config holds the full portcullis-keep configuration loaded from keep.yaml.
type Config struct {
	Mode           string                     `yaml:"mode"`
	Server         cfgloader.ServerConfig     `yaml:"server"`
	Identity       IdentityConfig             `yaml:"identity"`
	Peers          PeersConfig                `yaml:"peers"`
	Responsibility ResponsibilityConfig       `yaml:"responsibility"`
	Operations     cfgloader.OperationsConfig `yaml:"operations"`

	// Derived / internal use only
	DecisionLog cfgloader.DecisionLogConfig `yaml:"-"`
	Limits      LimitsConfig                `yaml:"-"`
}

// ResponsibilityConfig defines the specialized duty of Portcullis-Keep.
type ResponsibilityConfig struct {
	Policy           PolicyConfig           `yaml:"policy"`
	GateStaticPolicy GateStaticPolicyConfig `yaml:"gate_static_policy"`
	Backends         []BackendConfig        `yaml:"mcp_backends"`
	Issuance         IssuanceConfig         `yaml:"issuance"`
	Workflow         EscalationConfig       `yaml:"workflow"`
}

// IssuanceConfig holds signing logic for escalation requests.
type IssuanceConfig struct {
	SigningKey string `yaml:"signing_key"`
	TTL        int    `yaml:"ttl"`
}

// PeersConfig defines outbound connectivity to other Portcullis services.
type PeersConfig struct {
	Guard         cfgloader.GuardPeerConfig         `yaml:"guard"`
	Normalization cfgloader.NormalizationPeerConfig `yaml:"normalization"`
}

// Validate returns a PostureReport and an error if the configuration contains invalid values.
func (c *Config) Validate(sources cfgloader.SourceMap) (cfgloader.PostureReport, error) {
	if c.Mode == "" {
		c.Mode = cfgloader.ModeProduction
	}

	if c.Mode == cfgloader.ModeProduction {
		if c.Identity.Strategy == "passthrough" {
			return cfgloader.PostureReport{}, fmt.Errorf("identity.strategy \"passthrough\" is not allowed in production mode")
		}
		if c.Responsibility.Policy.Strategy == "noop" {
			return cfgloader.PostureReport{}, fmt.Errorf("policy.strategy \"noop\" is not allowed in production mode")
		}
		normEP := c.Peers.Normalization.Endpoint
		if normEP != "" && !strings.HasPrefix(normEP, "https://") {
			return cfgloader.PostureReport{}, fmt.Errorf("peers.normalization.endpoint must use https:// in production mode (got %q)", normEP)
		}
		if val, ok := c.Identity.Config["allow_insecure_jwks_url"]; ok {
			if b, ok := val.(bool); ok && b {
				return cfgloader.PostureReport{}, fmt.Errorf("identity.config.allow_insecure_jwks_url is not allowed in production mode")
			}
		}
		for name, ep := range c.Server.Endpoints {
			if ep.Auth.Type == "none" {
				return cfgloader.PostureReport{}, fmt.Errorf("auth.type \"none\" for endpoint %q is not allowed in production mode", name)
			}
			if !cfgloader.IsLoopback(ep.Listen) && !ep.IsSecure() {
				return cfgloader.PostureReport{}, fmt.Errorf("TLS is required for non-loopback endpoint %q in production mode", name)
			}
		}
	}

	if normEP := c.Peers.Normalization.Endpoint; normEP != "" {
		switch c.Peers.Normalization.Auth.Type {
		case "", "none":
			// valid; no credentials required
		case "bearer":
			if c.Peers.Normalization.Auth.Credentials.BearerToken == "" {
				return cfgloader.PostureReport{}, fmt.Errorf("peers.normalization.auth.credentials.bearer_token is required when auth.type is \"bearer\"")
			}
		case "mtls":
			return cfgloader.PostureReport{}, fmt.Errorf("peers.normalization.auth.type \"mtls\" is not supported for webhook peers; use \"none\" or \"bearer\"")
		default:
			return cfgloader.PostureReport{}, fmt.Errorf("peers.normalization.auth.type %q is not valid; must be \"none\" or \"bearer\"", c.Peers.Normalization.Auth.Type)
		}
	}

	if _, ok := c.Server.Endpoints["main"]; !ok {
		return cfgloader.PostureReport{}, fmt.Errorf("server.endpoints.main is required")
	}

	if err := c.Identity.Validate(); err != nil {
		return cfgloader.PostureReport{}, err
	}
	if err := c.Responsibility.Policy.Validate(); err != nil {
		return cfgloader.PostureReport{}, err
	}
	if err := c.Responsibility.GateStaticPolicy.Validate(); err != nil {
		return cfgloader.PostureReport{}, fmt.Errorf("gate_static_policy: %w", err)
	}
	if err := c.Responsibility.Workflow.Validate(); err != nil {
		return cfgloader.PostureReport{}, err
	}

	if c.Operations.Limits != nil {
		if err := mapstructure.Decode(c.Operations.Limits, &c.Limits); err != nil {
			return cfgloader.PostureReport{}, fmt.Errorf("decode operations.limits: %w", err)
		}
	}
	c.Limits.ApplyDefaults()

	if logCfg, ok := c.Operations.Storage.Config["decision_log"]; ok {
		if err := mapstructure.Decode(logCfg, &c.DecisionLog); err != nil {
			return cfgloader.PostureReport{}, fmt.Errorf("decode operations.storage.config.decision_log: %w", err)
		}
	}

	for i := range c.Responsibility.Backends {
		if err := validateBackendConfig(&c.Responsibility.Backends[i]); err != nil {
			return cfgloader.PostureReport{}, fmt.Errorf("mcp_backends[%d] (%q): %w", i, c.Responsibility.Backends[i].Name, err)
		}
	}

	report := cfgloader.BuildPostureReport(c, sources, SecretAllowlist)

	if c.Mode != cfgloader.ModeProduction {
		report.SetStatus("mode", "WARN", "Use production mode for deployments")
	}
	if c.Identity.Strategy == "passthrough" {
		report.SetStatus("identity.strategy", "WARN", "Passthrough identity is not suitable for production; use oidc-verify or hmac-verify")
		if c.Peers.Normalization.Endpoint != "" {
			report.SetStatus("peers.normalization.endpoint", "WARN", "Normalization webhook is configured but has no effect: passthrough identity does not invoke the webhook")
		}
	}
	if c.Responsibility.Policy.Strategy == "noop" {
		report.SetStatus("responsibility.policy.strategy", "WARN", "Noop policy allows all requests; configure OPA for production")
	}
	for name, ep := range c.Server.Endpoints {
		if ep.Auth.Type == "none" {
			report.SetStatus("server.endpoints."+name+".auth.type", "WARN", "Configure authentication for this endpoint in production")
		}
		if !ep.IsSecure() {
			report.SetStatus("server.endpoints."+name+".tls.cert", "WARN", "Enable TLS for this endpoint in production")
		}
	}

	return report, nil
}

type IdentityConfig struct {
	Strategy string         `yaml:"strategy"` // "passthrough" | "oidc-verify" | "hmac-verify"
	Config   map[string]any `yaml:"config"`

	// Derived
	Normalizer identity.NormalizerConfig `yaml:"-"`
}

func (c *IdentityConfig) Validate() error {
	if c.Strategy == "" {
		return fmt.Errorf("identity.strategy is required")
	}

	if c.Config != nil {
		switch c.Strategy {
		case "oidc-verify":
			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				Result:  &c.Normalizer.OIDCVerify,
				TagName: "yaml",
			})
			if err != nil {
				return err
			}
			if err := decoder.Decode(c.Config); err != nil {
				return fmt.Errorf("decode identity.config for oidc-verify: %w", err)
			}
		case "passthrough":
			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				Result:  &c.Normalizer,
				TagName: "yaml",
			})
			if err != nil {
				return err
			}
			if err := decoder.Decode(c.Config); err != nil {
				return fmt.Errorf("decode identity.config for passthrough: %w", err)
			}
		case "hmac-verify":
			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				Result:  &c.Normalizer.HMACVerify,
				TagName: "yaml",
			})
			if err != nil {
				return err
			}
			if err := decoder.Decode(c.Config); err != nil {
				return fmt.Errorf("decode identity.config for hmac-verify: %w", err)
			}
		}
	}

	// Ensure Normalizer field is set after any possible overwrites from Decode.
	c.Normalizer.Normalizer = c.Strategy

	// Decode cache and validation limit fields that live at the top level of
	// identity.config alongside strategy-specific settings.
	if c.Config != nil {
		limitDecoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			Result:  &c.Normalizer,
			TagName: "yaml",
		})
		if err != nil {
			return err
		}
		if err := limitDecoder.Decode(c.Config); err != nil {
			return fmt.Errorf("decode identity.config cache/validation fields: %w", err)
		}
	}

	return c.Normalizer.Validate()
}

type PolicyConfig struct {
	Strategy string         `yaml:"strategy"` // "opa" | "noop"
	Config   map[string]any `yaml:"config"`

	// Derived
	OPA OPAConfig `yaml:"-"`
}

type OPAConfig struct {
	Endpoint string `yaml:"endpoint" mapstructure:"endpoint"`
}

func (c *PolicyConfig) Validate() error {
	if c.Config != nil {
		if err := mapstructure.Decode(c.Config, &c.OPA); err != nil {
			return fmt.Errorf("decode policy.config: %w", err)
		}
	}
	if c.Strategy != "noop" && c.OPA.Endpoint == "" {
		return fmt.Errorf("policy.config.endpoint is required when policy.strategy is not \"noop\"")
	}
	return nil
}

// GateStaticPolicyConfig configures the PDP used for Gate's static tool policy distribution.
// The PDP itself controls which resource names are served; unknown resources receive an
// empty policy rather than an error.
type GateStaticPolicyConfig struct {
	PolicyConfig `yaml:",inline" mapstructure:",inline"`
}

// Validate validates the gate_static_policy block. It is a no-op if strategy is empty
// (i.e., the block is not configured).
func (c *GateStaticPolicyConfig) Validate() error {
	if c.Strategy == "" {
		return nil
	}
	return c.PolicyConfig.Validate()
}

type EscalationConfig struct {
	Strategy string         `yaml:"strategy"` // "servicenow" | "webhook" | "url" | "noop"
	Config   map[string]any `yaml:"config"`

	// Derived
	ServiceNow ServiceNowConfig  `yaml:"-"`
	Webhook    WebhookConfig     `yaml:"-"`
	URL        URLWorkflowConfig `yaml:"-"`
}

func (c *EscalationConfig) Validate() error {
	if c.Config != nil {
		switch c.Strategy {
		case "servicenow":
			if err := mapstructure.Decode(c.Config, &c.ServiceNow); err != nil {
				return fmt.Errorf("decode escalation.config for servicenow: %w", err)
			}
		case "webhook":
			if err := mapstructure.Decode(c.Config, &c.Webhook); err != nil {
				return fmt.Errorf("decode escalation.config for webhook: %w", err)
			}
		case "url":
			if err := mapstructure.Decode(c.Config, &c.URL); err != nil {
				return fmt.Errorf("decode escalation.config for url: %w", err)
			}
		}
	}

	switch c.Strategy {
	case "", "noop", "url", "servicenow", "webhook":
		// valid
	default:
		return fmt.Errorf("invalid escalation.strategy %q: must be \"noop\", \"url\", \"servicenow\", or \"webhook\"", c.Strategy)
	}
	if c.Strategy == "servicenow" && c.ServiceNow.Instance == "" {
		return fmt.Errorf("escalation.config.instance is required when strategy is \"servicenow\"")
	}
	if c.Strategy == "webhook" && c.Webhook.URL == "" {
		return fmt.Errorf("escalation.config.url is required when strategy is \"webhook\"")
	}
	return nil
}

type BackendConfig struct {
	Name                  string            `yaml:"name"`
	Type                  string            `yaml:"type"`    // "stdio" | "http" | "sse"
	Command               string            `yaml:"command"` // for stdio
	Args                  []string          `yaml:"args"`
	Env                   map[string]string `yaml:"env"`
	URL                   string            `yaml:"url"` // for http
	AllowPrivateAddresses bool              `yaml:"allow_private_addresses"`
	ToolMap               map[string]string `yaml:"tool_map"`
	// ForwardHeaders filters which headers from EnrichedMCPRequest.ClientHeaders are
	// sent to this backend. Supports exact names, prefix wildcards (x-tenant-*), or
	// "*" for all non-forbidden headers. Default: ["*"]
	ForwardHeaders []string `yaml:"forward_headers"`
	// DropHeaders lists headers that must never be sent to this backend, regardless
	// of ForwardHeaders. Evaluated after the Forbidden hard-coded list. Default: []
	DropHeaders []string `yaml:"drop_headers"`
	// UserIdentity configures how Keep injects the caller's identity into requests
	// forwarded to this backend, and optionally exchanges the raw token for a
	// backend-specific value via an exchange service.
	UserIdentity BackendUserIdentity `yaml:"user_identity"`

	ToolList    ToolListConfig `yaml:"tool_list"`
	StaticTools []*mcp.Tool    `yaml:"-"` // Loaded directly if Source == "file"
}

type ToolListConfig struct {
	Source string `yaml:"source"` // "file" | "remote"
	File   string `yaml:"file"`
}

// BackendUserIdentity groups all per-backend identity injection and exchange settings.
//
// Type selects the authentication strategy:
//   - "" or "none"     – no identity injection (default / legacy)
//   - "exchange"       – exchange raw token via an HTTP service (legacy explicit form)
//   - "api_key"        – inject a static API key from APIKey.Source
//   - "oauth"          – OAuth 2.1 PKCE flow managed by Keep
//
// Placement controls where the resolved identity value is injected into outgoing
// requests.  Exchange configures the optional token-exchange service (used when
// Type is "" or "exchange").
type BackendUserIdentity struct {
	Type      string                   `yaml:"type"` // none | exchange | api_key | oauth
	Placement BackendIdentityPlacement `yaml:"placement"`
	Exchange  BackendIdentityExchange  `yaml:"exchange"`
	OAuth     BackendOAuth             `yaml:"oauth"`
	APIKey    BackendAPIKey            `yaml:"api_key"`
}

// BackendOAuth configures an OAuth 2.1 PKCE authorization-code flow for a backend.
type BackendOAuth struct {
	// ClientID is the OAuth client identifier registered with the authorization server.
	ClientID string `yaml:"client_id"`
	// AuthorizationEndpoint is the URL of the authorization endpoint.
	AuthorizationEndpoint string `yaml:"authorization_endpoint"`
	// TokenEndpoint is the URL used for code-for-token exchange.
	TokenEndpoint string `yaml:"token_endpoint"`
	// CallbackURL is the redirect URI registered with the authorization server.
	// Keep's /oauth/callback handler must be reachable at this URL.
	CallbackURL string `yaml:"callback_url"`
	// Scopes is the list of OAuth scopes to request.
	Scopes []string `yaml:"scopes"`
	// RefreshWindowSecs is the number of seconds before expiry at which Keep will
	// proactively refresh the access token.  0 disables proactive refresh.
	RefreshWindowSecs int `yaml:"refresh_window_secs"`
	// FlowTimeoutSecs is the maximum number of seconds to wait for the user to
	// complete the browser-based authorization flow.  0 uses the store default (10 min).
	FlowTimeoutSecs int `yaml:"flow_timeout_secs"`
	// StoreRefreshTokens controls whether Keep persists the refresh token in the
	// CredentialsStore.  Set to false if the authorization server does not issue them.
	StoreRefreshTokens bool `yaml:"store_refresh_tokens"`
}

// RefreshWindow returns RefreshWindowSecs as a time.Duration.
func (o *BackendOAuth) RefreshWindow() time.Duration {
	return time.Duration(o.RefreshWindowSecs) * time.Second
}

// FlowTimeout returns FlowTimeoutSecs as a time.Duration, defaulting to 10 minutes.
func (o *BackendOAuth) FlowTimeout() time.Duration {
	if o.FlowTimeoutSecs <= 0 {
		return 10 * time.Minute
	}
	return time.Duration(o.FlowTimeoutSecs) * time.Second
}

// BackendAPIKey configures static API key injection for a backend.
// The Source field contains the resolved API key value (supports ${VAR} syntax at
// config load time).  Use Placement.Header to specify the destination header name.
type BackendAPIKey struct {
	// Source is the API key value to inject (e.g. "Bearer ${MY_SECRET_KEY}").
	Source string `yaml:"source"`
}

// BackendIdentityPlacement specifies where the identity value is placed in outgoing requests.
// Exactly one of Header or JSONPath must be set; setting both is a configuration error.
type BackendIdentityPlacement struct {
	// Header, if non-empty, injects the identity value as an HTTP header of this
	// name. Applies to http and sse backends only.
	Header string `yaml:"header"`
	// JSONPath, if non-empty, injects the identity value at this dot-separated
	// path in the tool call arguments. Applies to all backend types.
	JSONPath string `yaml:"json_path"`
}

// BackendIdentityExchange configures the optional identity exchange service for a backend.
// Keep POSTs {"token":"<raw>"} to URL and injects the returned {"identity":"<value>"}.
// If exchange fails for any reason, injection is omitted entirely (fail-degraded).
type BackendIdentityExchange struct {
	// URL is the HTTP endpoint of the exchange service. Required to enable exchange.
	URL string `yaml:"url"`
	// Timeout is the HTTP timeout in seconds for calls to the exchange service.
	// 0 uses the default (5 seconds).
	Timeout int `yaml:"timeout"`
	// Cache controls caching of exchanged identities.
	Cache BackendIdentityExchangeCache `yaml:"cache"`
	// AuthHeaders are additional HTTP headers sent to the exchange service (e.g. Authorization).
	AuthHeaders map[string]string `yaml:"auth_headers"`
}

// BackendIdentityExchangeCache configures caching of exchanged identity values.
type BackendIdentityExchangeCache struct {
	// TTL is the maximum number of seconds to cache an exchanged identity.
	// The effective TTL is also capped by the source token's exp claim.
	// 0 disables caching.
	TTL int `yaml:"ttl"`
	// MaxEntries is the maximum number of entries in the in-memory cache.
	// 0 uses the default (1000). Ignored when Redis storage is configured.
	MaxEntries int `yaml:"max_entries"`
}

type ServiceNowConfig struct {
	Instance      string `yaml:"instance" mapstructure:"instance"`
	CredentialEnv string `yaml:"credential_env" mapstructure:"credential_env"`
}

type WebhookConfig struct {
	URL     string            `yaml:"url" mapstructure:"url"`
	Headers map[string]string `yaml:"headers" mapstructure:"headers"`
}

type URLWorkflowConfig struct {
	Endpoints cfgloader.GuardEndpoints `yaml:"endpoints" mapstructure:"endpoints"`
}

type SigningConfig = shared.SigningConfig

// LimitsConfig controls request body and field length limits for Keep.
// Zero values are replaced with service defaults by ApplyDefaults.
type LimitsConfig struct {
	MaxRequestBodyBytes           int `yaml:"max_request_body_bytes" mapstructure:"max_request_body_bytes"`                       // default: 1048576 (1 MB)
	MaxServerNameBytes            int `yaml:"max_server_name_bytes" mapstructure:"max_server_name_bytes"`                         // default: 256
	MaxToolNameBytes              int `yaml:"max_tool_name_bytes" mapstructure:"max_tool_name_bytes"`                             // default: 256
	MaxUserIDBytes                int `yaml:"max_user_id_bytes" mapstructure:"max_user_id_bytes"`                                 // default: 512
	MaxTraceIDBytes               int `yaml:"max_trace_id_bytes" mapstructure:"max_trace_id_bytes"`                               // default: 128
	MaxSessionIDBytes             int `yaml:"max_session_id_bytes" mapstructure:"max_session_id_bytes"`                           // default: 128
	MaxReasonBytes                int `yaml:"max_reason_bytes" mapstructure:"max_reason_bytes"`                                   // default: 4096
	MaxLogBatchSize               int `yaml:"max_log_batch_size" mapstructure:"max_log_batch_size"`                               // default: 1000
	MaxForwardedHeaders           int `yaml:"max_forwarded_headers" mapstructure:"max_forwarded_headers"`                         // default: 20
	MaxHeaderNameBytes            int `yaml:"max_header_name_bytes" mapstructure:"max_header_name_bytes"`                         // default: 128
	MaxHeaderValueBytes           int `yaml:"max_header_value_bytes" mapstructure:"max_header_value_bytes"`                       // default: 4096
	MaxForwardedHeadersTotalBytes int `yaml:"max_forwarded_headers_total_bytes" mapstructure:"max_forwarded_headers_total_bytes"` // default: 16384 (16 KB)
}

// ApplyDefaults fills any zero-value fields with their service defaults.
func (l *LimitsConfig) ApplyDefaults() {
	if l.MaxRequestBodyBytes == 0 {
		l.MaxRequestBodyBytes = 1 << 20 // 1 MB
	}
	if l.MaxServerNameBytes == 0 {
		l.MaxServerNameBytes = 256
	}
	if l.MaxToolNameBytes == 0 {
		l.MaxToolNameBytes = 256
	}
	if l.MaxUserIDBytes == 0 {
		l.MaxUserIDBytes = 512
	}
	if l.MaxTraceIDBytes == 0 {
		l.MaxTraceIDBytes = 128
	}
	if l.MaxSessionIDBytes == 0 {
		l.MaxSessionIDBytes = 128
	}
	if l.MaxReasonBytes == 0 {
		l.MaxReasonBytes = 4096
	}
	if l.MaxLogBatchSize == 0 {
		l.MaxLogBatchSize = 1000
	}
	if l.MaxForwardedHeaders == 0 {
		l.MaxForwardedHeaders = 20
	}
	if l.MaxHeaderNameBytes == 0 {
		l.MaxHeaderNameBytes = 128
	}
	if l.MaxHeaderValueBytes == 0 {
		l.MaxHeaderValueBytes = 4096
	}
	if l.MaxForwardedHeadersTotalBytes == 0 {
		l.MaxForwardedHeadersTotalBytes = 16384 // 16 KB
	}
}

// validateBackendConfig checks that user_identity placement, exchange, OAuth,
// api_key, and tool_list settings are well-formed and safe when set on a BackendConfig.
func validateBackendConfig(cfg *BackendConfig) error {
	h := cfg.UserIdentity.Placement.Header
	p := cfg.UserIdentity.Placement.JSONPath

	if h != "" && p != "" {
		return fmt.Errorf("user_identity.placement: header and json_path are mutually exclusive — set one or the other, not both")
	}

	if h != "" {
		if strings.TrimSpace(h) == "" {
			return fmt.Errorf("user_identity.placement.header must not be whitespace-only")
		}
		if shared.IsForbiddenHeader(h) {
			return fmt.Errorf("user_identity.placement.header %q is a forbidden header and cannot be used for identity injection", h)
		}
	}
	if p != "" {
		if err := validateIdentityPath(p); err != nil {
			return fmt.Errorf("user_identity.placement.json_path: %w", err)
		}
	}

	switch cfg.UserIdentity.Type {
	case "", "none":
		// No identity injection; exchange URL may still be set (legacy zero-type behaviour).
		if u := cfg.UserIdentity.Exchange.URL; u != "" {
			if h == "" && p == "" {
				return fmt.Errorf("user_identity.exchange.url is set but neither header nor json_path is configured — at least one placement must be set")
			}
			if err := checkBackendURL(u, cfg.AllowPrivateAddresses); err != nil {
				return fmt.Errorf("user_identity.exchange.url: %w", err)
			}
		}
	case "exchange":
		u := cfg.UserIdentity.Exchange.URL
		if u == "" {
			return fmt.Errorf("user_identity.type \"exchange\" requires user_identity.exchange.url to be set")
		}
		if h == "" && p == "" {
			return fmt.Errorf("user_identity.exchange.url is set but neither header nor json_path is configured — at least one placement must be set")
		}
		if err := checkBackendURL(u, cfg.AllowPrivateAddresses); err != nil {
			return fmt.Errorf("user_identity.exchange.url: %w", err)
		}
	case "api_key":
		if cfg.UserIdentity.APIKey.Source == "" {
			return fmt.Errorf("user_identity.type \"api_key\" requires user_identity.api_key.source to be set")
		}
		if h == "" {
			return fmt.Errorf("user_identity.type \"api_key\" requires user_identity.placement.header to specify the destination header")
		}
	case "oauth":
		o := cfg.UserIdentity.OAuth
		if o.ClientID == "" {
			return fmt.Errorf("user_identity.oauth.client_id is required when type is \"oauth\"")
		}
		if o.AuthorizationEndpoint == "" {
			return fmt.Errorf("user_identity.oauth.authorization_endpoint is required when type is \"oauth\"")
		}
		if o.TokenEndpoint == "" {
			return fmt.Errorf("user_identity.oauth.token_endpoint is required when type is \"oauth\"")
		}
		if o.CallbackURL == "" {
			return fmt.Errorf("user_identity.oauth.callback_url is required when type is \"oauth\"")
		}
	default:
		return fmt.Errorf("user_identity.type %q is invalid; must be one of: none, exchange, api_key, oauth", cfg.UserIdentity.Type)
	}

	if cfg.ToolList.Source == "file" {
		if cfg.ToolList.File == "" {
			return fmt.Errorf("tool_list.file is required when source is 'file'")
		}

		attemptedPath, err := filepath.Abs(cfg.ToolList.File)
		if err != nil {
			return fmt.Errorf("failed to resolve absolute path for static tool list file: configured=%q: %w", cfg.ToolList.File, err)
		}
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to determine current working directory for path resolution: %w", err)
		}

		data, err := os.ReadFile(attemptedPath)
		if err != nil {
			return fmt.Errorf("failed to read static tool list file: configured=%q attempted=%q base_dir=%q (cwd): %w", cfg.ToolList.File, attemptedPath, cwd, err)
		}
		var result mcp.ListToolsResult
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("failed to parse static tool list file: configured=%q attempted=%q: %w", cfg.ToolList.File, attemptedPath, err)
		}
		cfg.StaticTools = result.Tools
	} else if cfg.ToolList.Source != "" && cfg.ToolList.Source != "remote" {
		return fmt.Errorf("tool_list.source %q is invalid; must be 'file' or 'remote'", cfg.ToolList.Source)
	}

	return nil
}

// validateIdentityPath returns an error if path is whitespace-only, contains
// empty segments (e.g. ".a", "a.", "a..b"), or contains characters outside the
// allowed set [a-zA-Z0-9_-] within any segment.  These constraints ensure that
// every segment maps to a predictable, well-formed map key after injection.
func validateIdentityPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("identity_path must not be whitespace-only")
	}
	for _, seg := range strings.Split(path, ".") {
		if seg == "" {
			return fmt.Errorf("path %q contains an empty segment", path)
		}
		for _, r := range seg {
			if !isValidPathSegmentChar(r) {
				return fmt.Errorf("path %q contains invalid character %q in segment %q (allowed: a-z, A-Z, 0-9, _, -)", path, r, seg)
			}
		}
	}
	return nil
}

// isValidPathSegmentChar reports whether r is allowed inside a path segment.
// Permitted characters: ASCII letters, digits, underscore, hyphen.
func isValidPathSegmentChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') || r == '_' || r == '-'
}

// RedisConfig holds connection and security settings for a Redis-backed store.
// Fields map directly to the keys in operations.storage.config in keep.yaml.
type RedisConfig struct {
	Addr          string `yaml:"addr"            mapstructure:"addr"`
	Password      string `yaml:"password"        mapstructure:"password"`
	DB            int    `yaml:"db"              mapstructure:"db"`
	KeyPrefix     string `yaml:"key_prefix"      mapstructure:"key_prefix"`
	TLSEnabled    bool   `yaml:"tls_enabled"     mapstructure:"tls_enabled"`
	TLSSkipVerify bool   `yaml:"tls_skip_verify" mapstructure:"tls_skip_verify"`
	TLSCACert     string `yaml:"tls_ca_cert"     mapstructure:"tls_ca_cert"`
}
