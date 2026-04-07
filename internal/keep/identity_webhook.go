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
	"net/http"
	"strings"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

const (
	defaultNormalizationTimeoutSecs = 10
	defaultNormalizationMaxPayloadKB = 128
)

// NormalizationClient posts filtered JWT claims to an enterprise webhook and
// returns the resulting shared.Principal. The caller is responsible for
// applying claim filters before calling Normalize.
type NormalizationClient struct {
	endpoint   string
	authType   string // "none" or "bearer"
	token      string
	maxBytes   int
	httpClient *http.Client
}

// newNormalizationClient constructs a NormalizationClient from peer config.
// Returns an error if:
//   - mode is "production" and the endpoint is not HTTPS
//   - auth.type is "mtls" (not supported for webhook peers)
//   - auth.type is an unrecognized value
//   - auth.type is "bearer" but no bearer_token is configured
func newNormalizationClient(cfg cfgloader.NormalizationPeerConfig, mode string) (*NormalizationClient, error) {
	if mode == cfgloader.ModeProduction && !strings.HasPrefix(cfg.Endpoint, "https://") {
		return nil, fmt.Errorf("peers.normalization.endpoint must use https:// in production mode (got %q)", cfg.Endpoint)
	}

	authType := cfg.Auth.Type
	switch authType {
	case "", "none":
		authType = "none"
	case "bearer":
		if cfg.Auth.Credentials.BearerToken == "" {
			return nil, fmt.Errorf("peers.normalization.auth.credentials.bearer_token is required when auth.type is \"bearer\"")
		}
	case "mtls":
		return nil, fmt.Errorf("peers.normalization.auth.type \"mtls\" is not supported for webhook peers; use \"none\" or \"bearer\"")
	default:
		return nil, fmt.Errorf("peers.normalization.auth.type %q is not valid; must be \"none\" or \"bearer\"", authType)
	}

	timeout := defaultNormalizationTimeoutSecs
	if cfg.Timeout > 0 {
		timeout = cfg.Timeout
	}
	maxKB := defaultNormalizationMaxPayloadKB
	if cfg.MaxPayloadKB > 0 {
		maxKB = cfg.MaxPayloadKB
	}

	return &NormalizationClient{
		endpoint: cfg.Endpoint,
		authType: authType,
		token:    cfg.Auth.Credentials.BearerToken,
		maxBytes: maxKB * 1024,
		httpClient: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
	}, nil
}

// Normalize POSTs claims to the webhook endpoint and deserializes the response
// into a shared.Principal. It enforces the configured payload size limit on
// both the request and the response bodies.
//
// A non-200 response or a timeout causes an error; the caller should treat this
// as a 503 (fail-closed).
func (c *NormalizationClient) Normalize(ctx context.Context, claims map[string]any) (shared.Principal, error) {
	body, err := json.Marshal(claims)
	if err != nil {
		return shared.Principal{}, fmt.Errorf("normalization webhook: marshal claims: %w", err)
	}
	if len(body) > c.maxBytes {
		return shared.Principal{}, fmt.Errorf("normalization webhook: request payload %d bytes exceeds limit of %d bytes", len(body), c.maxBytes)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return shared.Principal{}, fmt.Errorf("normalization webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.authType == "bearer" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return shared.Principal{}, fmt.Errorf("normalization webhook: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return shared.Principal{}, fmt.Errorf("normalization webhook: unexpected status %d", resp.StatusCode)
	}

	// Read at most maxBytes+1 so we can detect an oversize response without
	// buffering the entire body into memory first.
	limited := io.LimitReader(resp.Body, int64(c.maxBytes)+1)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return shared.Principal{}, fmt.Errorf("normalization webhook: read response: %w", err)
	}
	if len(respBody) > c.maxBytes {
		return shared.Principal{}, fmt.Errorf("normalization webhook: response payload exceeds limit of %d bytes", c.maxBytes)
	}

	var principal shared.Principal
	if err := json.Unmarshal(respBody, &principal); err != nil {
		return shared.Principal{}, fmt.Errorf("normalization webhook: unmarshal response: %w", err)
	}

	return principal, nil
}
