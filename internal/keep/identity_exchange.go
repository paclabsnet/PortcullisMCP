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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
	"go.opentelemetry.io/otel/trace"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

const (
	defaultExchangeTimeoutSecs     = 5
	defaultExchangeCacheMaxEntries = 1000
	maxExchangeResponseBytes       = 16 * 1024
)

// ExchangedIdentity is the result of a successful identity exchange.
//
// Str is always set and holds the string form of the identity — for plain-text
// and XML responses this is the full body; for JSON string results it is the
// trimmed value; for JSON object/array results it is the compact JSON
// serialisation (used for caching and as a fallback representation).
//
// Structured is non-nil only for JSON object/array responses. When set it
// holds the parsed Go value (map[string]any or []any) and MUST be used for
// structural json_path injection rather than Str. Structured values MUST NOT
// be injected as HTTP header values.
type ExchangedIdentity struct {
	Str        string
	Structured any
}

// exchangeCacheValue is the JSON envelope used to persist an ExchangedIdentity
// in the string-valued cache layer (memory LRU or Redis).
type exchangeCacheValue struct {
	Str        string `json:"s"`
	Structured any    `json:"j,omitempty"`
}

func encodeExchangeCacheValue(id *ExchangedIdentity) (string, error) {
	b, err := json.Marshal(exchangeCacheValue{Str: id.Str, Structured: id.Structured})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeExchangeCacheValue(s string) (*ExchangedIdentity, error) {
	var v exchangeCacheValue
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, err
	}
	return &ExchangedIdentity{Str: v.Str, Structured: v.Structured}, nil
}

// IdentityExchanger transforms a raw identity token into the backend-specific
// ExchangedIdentity that will be injected into outgoing requests. Every
// registered backend has exactly one IdentityExchanger: backends with
// user_identity.exchange.url get an IdentityExchangeClient; all others get a
// noopIdentityExchanger that wraps the raw token unchanged.
type IdentityExchanger interface {
	Exchange(ctx context.Context, rawToken string) (*ExchangedIdentity, bool)
}

// noopIdentityExchanger passes the raw token through as a plain string identity.
// It is the default for backends that do not have an exchange URL configured.
type noopIdentityExchanger struct{}

func (noopIdentityExchanger) Exchange(_ context.Context, rawToken string) (*ExchangedIdentity, bool) {
	return &ExchangedIdentity{Str: rawToken}, true
}

// failDegradedExchanger always returns fail-degraded. It is the initial state
// for exchange-configured backends before the first Reload builds the real client,
// ensuring no identity is injected rather than forwarding the raw token.
type failDegradedExchanger struct {
	backendName string
}

func (e failDegradedExchanger) Exchange(ctx context.Context, _ string) (*ExchangedIdentity, bool) {
	traceID := trace.SpanFromContext(ctx).SpanContext().TraceID().String()
	slog.Warn("keep: identity exchange unavailable (client initialization failed)",
		"backend", e.backendName, "trace_id", traceID)
	return nil, false
}

// IdentityExchangeClient exchanges a raw identity token for a backend-specific
// identity value by calling a configured HTTP exchange service.
type IdentityExchangeClient struct {
	url         string
	headers     map[string]string
	backendName string
	httpClient  *http.Client
	cache       IdentityExchangeCacher
	cacheTTL    time.Duration
}

// newIdentityExchangeClient constructs an IdentityExchangeClient for the given backend config.
// The HTTP client is configured with no-redirect policy and the specified (or default) timeout.
// The cache backend is selected from storage; passing an empty StorageConfig produces an
// in-memory LRU cache.
func newIdentityExchangeClient(ctx context.Context, cfg BackendConfig, storage cfgloader.StorageConfig) (*IdentityExchangeClient, error) {
	timeoutSecs := cfg.UserIdentity.Exchange.Timeout
	if timeoutSecs <= 0 {
		timeoutSecs = defaultExchangeTimeoutSecs
	}

	httpClient := noRedirectHTTPClient()
	httpClient.Timeout = time.Duration(timeoutSecs) * time.Second

	cacheTTL := time.Duration(cfg.UserIdentity.Exchange.Cache.TTL) * time.Second

	var cache IdentityExchangeCacher
	if cacheTTL > 0 {
		maxEntries := cfg.UserIdentity.Exchange.Cache.MaxEntries
		if maxEntries <= 0 {
			maxEntries = defaultExchangeCacheMaxEntries
		}
		var err error
		cache, err = buildIdentityExchangeCache(ctx, storage, maxEntries, cfg.Name)
		if err != nil {
			return nil, fmt.Errorf("build identity exchange cache for backend %q: %w", cfg.Name, err)
		}
	}

	return &IdentityExchangeClient{
		url:         cfg.UserIdentity.Exchange.URL,
		headers:     cfg.UserIdentity.Exchange.AuthHeaders,
		backendName: cfg.Name,
		httpClient:  httpClient,
		cache:       cache,
		cacheTTL:    cacheTTL,
	}, nil
}

// buildIdentityExchangeCache constructs the IdentityExchangeCacher selected by storage.Backend.
func buildIdentityExchangeCache(ctx context.Context, storage cfgloader.StorageConfig, maxEntries int, backendName string) (IdentityExchangeCacher, error) {
	switch storage.Backend {
	case "redis":
		var redisCfg RedisConfig
		if err := mapstructure.Decode(storage.Config, &redisCfg); err != nil {
			return nil, fmt.Errorf("decode redis config: %w", err)
		}
		redisClient, err := newKeepRedisClient(ctx, redisCfg)
		if err != nil {
			return nil, err
		}
		return NewRedisIdentityExchangeCache(redisClient, redisCfg.KeyPrefix, backendName), nil
	case "memory", "":
		return NewIdentityExchangeCache(maxEntries), nil
	default:
		return nil, fmt.Errorf("unknown storage backend %q for identity exchange cache: must be \"memory\" or \"redis\"", storage.Backend)
	}
}

// Exchange returns the backend-specific ExchangedIdentity for rawToken.
// On any failure it logs a redacted error and returns (nil, false) so the caller
// can apply fail-degraded behaviour (omit identity injection entirely).
func (c *IdentityExchangeClient) Exchange(ctx context.Context, rawToken string) (*ExchangedIdentity, bool) {
	cacheKey := c.backendName + ":" + tokenCacheKey(rawToken)

	if c.cache != nil {
		if cached, ok := c.cache.Get(cacheKey); ok {
			if id, err := decodeExchangeCacheValue(cached); err == nil {
				return id, true
			}
			// Malformed cache entry — fall through and call the exchange service.
		}
	}

	identity, ok := c.callExchangeService(ctx, rawToken)
	if !ok {
		return nil, false
	}

	if c.cache != nil && c.cacheTTL > 0 {
		if encoded, err := encodeExchangeCacheValue(identity); err == nil {
			ttl := effectiveExchangeTTL(c.cacheTTL, rawToken)
			if ttl > 0 {
				c.cache.Add(cacheKey, encoded, ttl)
			}
		}
	}

	return identity, true
}

// callExchangeService performs the HTTP POST to the identity exchange endpoint.
// The response is dispatched to parseJSONResponse or parseTextResponse based on
// the Content-Type header. Returns (nil, false) on any failure; all error logs
// are redacted — they reference only backend_name and trace_id.
func (c *IdentityExchangeClient) callExchangeService(ctx context.Context, rawToken string) (*ExchangedIdentity, bool) {
	traceID := trace.SpanFromContext(ctx).SpanContext().TraceID().String()

	body, err := json.Marshal(map[string]string{"token": rawToken})
	if err != nil {
		slog.Warn("keep: identity exchange marshal error", "backend", c.backendName, "trace_id", traceID)
		return nil, false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		slog.Warn("keep: identity exchange request build error", "backend", c.backendName, "trace_id", traceID)
		return nil, false
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		slog.Warn("keep: identity exchange request failed", "backend", c.backendName, "trace_id", traceID)
		return nil, false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		slog.Warn("keep: identity exchange non-2xx response",
			"backend", c.backendName, "trace_id", traceID, "status", resp.StatusCode)
		return nil, false
	}

	// Limit reads to maxExchangeResponseBytes. Reading one byte beyond the limit
	// lets us detect oversized responses before committing to parse them.
	limited := io.LimitReader(resp.Body, maxExchangeResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		slog.Warn("keep: identity exchange response read error",
			"backend", c.backendName, "trace_id", traceID)
		return nil, false
	}
	if len(data) > maxExchangeResponseBytes {
		slog.Warn("keep: identity exchange response too large",
			"backend", c.backendName, "trace_id", traceID)
		return nil, false
	}

	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		return c.parseJSONResponse(traceID, data)
	}
	return c.parseTextResponse(traceID, data)
}

// parseJSONResponse handles application/json exchange responses.
// Expects {"identity": <string|object|array>} and returns an ExchangedIdentity
// where Structured is set for object/array results.
func (c *IdentityExchangeClient) parseJSONResponse(traceID string, data []byte) (*ExchangedIdentity, bool) {
	var parsed struct {
		Identity any `json:"identity"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		slog.Warn("keep: identity exchange malformed JSON response",
			"backend", c.backendName, "trace_id", traceID)
		return nil, false
	}
	if parsed.Identity == nil {
		slog.Warn("keep: identity exchange missing or null identity field",
			"backend", c.backendName, "trace_id", traceID)
		return nil, false
	}

	switch v := parsed.Identity.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			slog.Warn("keep: identity exchange empty identity value",
				"backend", c.backendName, "trace_id", traceID)
			return nil, false
		}
		return &ExchangedIdentity{Str: trimmed}, true
	case map[string]any, []any:
		// JSON object or array: re-serialise to compact JSON for Str (used in
		// caching and as a human-readable representation), and keep the parsed
		// value in Structured for injection into the MCP request body.
		b, err := json.Marshal(v)
		if err != nil {
			slog.Warn("keep: identity exchange re-marshal error",
				"backend", c.backendName, "trace_id", traceID)
			return nil, false
		}
		return &ExchangedIdentity{Str: string(b), Structured: v}, true
	default:
		// Booleans, numbers, and other scalar JSON types are not part of the
		// contract and are rejected to keep downstream behaviour predictable.
		slog.Warn("keep: identity exchange unexpected identity type",
			"backend", c.backendName, "trace_id", traceID)
		return nil, false
	}
}

// parseTextResponse handles non-JSON exchange responses (XML, text/plain, etc.).
// The entire response body is used as a plain string identity value.
func (c *IdentityExchangeClient) parseTextResponse(traceID string, data []byte) (*ExchangedIdentity, bool) {
	if !utf8.Valid(data) {
		slog.Warn("keep: identity exchange response is not valid UTF-8 and cannot be used as a string identity",
			"backend", c.backendName, "trace_id", traceID)
		return nil, false
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		slog.Warn("keep: identity exchange empty text response",
			"backend", c.backendName, "trace_id", traceID)
		return nil, false
	}
	return &ExchangedIdentity{Str: trimmed}, true
}

// effectiveExchangeTTL returns the TTL to use when caching an exchanged identity.
// If rawToken is a JWT with an exp claim, the TTL is capped so the cached identity
// cannot outlive the source token. Returns 0 if the source token is already expired.
func effectiveExchangeTTL(configured time.Duration, rawToken string) time.Duration {
	token, _, err := jwt.NewParser().ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		return configured
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return configured
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return configured
	}
	remaining := time.Until(exp.Time)
	if remaining <= 0 {
		return 0
	}
	if remaining < configured {
		return remaining
	}
	return configured
}
