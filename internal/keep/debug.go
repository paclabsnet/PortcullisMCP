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

// Package keep – debug.go contains helpers that emit structured slog.Debug
// messages about the OAuth / MCP flow.  All functions are no-ops when the
// active log level is above DEBUG, so they are safe to call unconditionally
// in hot paths.

package keep

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// debugEnabled reports whether DEBUG logging is active on the default logger.
// All helpers in this file gate on this to avoid unnecessary work.
func debugEnabled() bool {
	return slog.Default().Enabled(context.Background(), slog.LevelDebug)
}

// debugLogHeaders emits all headers in h as a single DEBUG log line under key label.
// If a header name matches sensitiveHeaders it is shown in full (debug mode only).
func debugLogHeaders(label string, h http.Header, extra ...any) {
	if !debugEnabled() {
		return
	}
	flat := make(map[string]string, len(h))
	for k, vs := range h {
		flat[k] = strings.Join(vs, ", ")
	}
	args := append([]any{"headers", flat}, extra...)
	slog.Debug(label, args...)
}

// debugLogRequest logs the outgoing HTTP request method, URL, and all headers.
// It does NOT consume the body.
func debugLogRequest(label string, req *http.Request) {
	if !debugEnabled() {
		return
	}
	args := []any{
		"method", req.Method,
		"url", req.URL.String(),
	}
	flat := make(map[string]string, len(req.Header))
	for k, vs := range req.Header {
		flat[k] = strings.Join(vs, ", ")
	}
	args = append(args, "headers", flat)
	slog.Debug(label, args...)
}

// debugLogResponse logs the HTTP response status code and all headers.
func debugLogResponse(label string, resp *http.Response, extra ...any) {
	if !debugEnabled() {
		return
	}
	flat := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		flat[k] = strings.Join(vs, ", ")
	}
	args := append([]any{"status", resp.StatusCode, "headers", flat}, extra...)
	slog.Debug(label, args...)
}

// debugLogResponseBody reads up to maxBytes from resp.Body, logs it, then
// replaces resp.Body with a new ReadCloser so the caller can still read it.
// Call this only when you own the response (i.e. before returning it to the SDK).
func debugLogResponseBody(label string, resp *http.Response, maxBytes int64) {
	if !debugEnabled() || resp == nil || resp.Body == nil {
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(data))
	if err != nil {
		slog.Debug(label, "body_read_err", err)
		return
	}
	slog.Debug(label, "body", string(data))
}

// debugLogRequestBody reads up to maxBytes from req.Body, logs it, then
// resets req.Body so the caller can still send it.
func debugLogRequestBody(label string, req *http.Request, maxBytes int64) {
	if !debugEnabled() || req.Body == nil {
		return
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, maxBytes))
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(data))
	if err != nil {
		slog.Debug(label, "body_read_err", err)
		return
	}
	slog.Debug(label, "body", string(data))
}

// debugLogBearerToken logs a Bearer token and, if it looks like a JWT,
// decodes and logs its header and payload claims without verifying the signature.
func debugLogBearerToken(label, token string, extra ...any) {
	if !debugEnabled() || token == "" {
		return
	}
	args := append([]any{"token", token}, extra...)
	// Attempt JWT decode (3 dot-separated base64url segments).
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		if hdr, err := decodeJWTPart(parts[0]); err == nil {
			args = append(args, "jwt_header", hdr)
		}
		if payload, err := decodeJWTPart(parts[1]); err == nil {
			args = append(args, "jwt_claims", payload)
			// Log notable claims individually for easy grepping.
			if sub, ok := payload["sub"].(string); ok {
				args = append(args, "sub", sub)
			}
			if exp, ok := payload["exp"]; ok {
				if expF, ok := toFloat64(exp); ok {
					t := time.Unix(int64(expF), 0).UTC()
					args = append(args, "exp", t.Format(time.RFC3339), "expires_in_secs", time.Until(t).Round(time.Second).String())
				}
			}
			if aud, ok := payload["aud"]; ok {
				args = append(args, "aud", aud)
			}
			if scp, ok := payload["scope"]; ok {
				args = append(args, "scope", scp)
			}
			if scp, ok := payload["scp"]; ok {
				args = append(args, "scp", scp)
			}
		}
	}
	slog.Debug(label, args...)
}

// debugLogOAuthToken logs a userToken's fields and decodes the access token as a JWT.
func debugLogOAuthToken(label string, tok *userToken, extra ...any) {
	if !debugEnabled() || tok == nil {
		return
	}
	args := []any{
		"expiry", tok.Expiry,
		"expiry_is_zero", tok.Expiry.IsZero(),
		"has_refresh_token", tok.RefreshToken != "",
	}
	args = append(args, extra...)
	slog.Debug(label, args...)
	debugLogBearerToken(label+" access_token", tok.AccessToken)
}

// debugLogClientReg logs the fields of a clientReg.
func debugLogClientReg(label string, reg *clientReg, extra ...any) {
	if !debugEnabled() || reg == nil {
		return
	}
	args := []any{
		"client_id", reg.ClientID,
		"has_secret", reg.ClientSecret != "",
		"secret_expires_at", reg.ClientSecretExpiresAt,
		"token_endpoint_auth_method", reg.TokenEndpointAuthMethod,
		"scopes", reg.Scopes,
	}
	args = append(args, extra...)
	slog.Debug(label, args...)
}

// debugLogDCRRequest logs the DCR registration request payload.
func debugLogDCRRequest(label string, payload dcrRegistrationRequest, endpoint string, hasIAT, hasSS bool) {
	if !debugEnabled() {
		return
	}
	slog.Debug(label,
		"endpoint", endpoint,
		"redirect_uris", payload.RedirectURIs,
		"client_name", payload.ClientName,
		"grant_types", payload.GrantTypes,
		"response_types", payload.ResponseTypes,
		"token_endpoint_auth_method", payload.TokenEndpointAuthMethod,
		"scope", payload.Scope,
		"has_initial_access_token", hasIAT,
		"has_software_statement", hasSS,
	)
}

// debugLogDCRResponse logs the DCR registration response.
func debugLogDCRResponse(label string, resp dcrRegistrationResponse, statusCode int) {
	if !debugEnabled() {
		return
	}
	slog.Debug(label,
		"http_status", statusCode,
		"client_id", resp.ClientID,
		"has_secret", resp.ClientSecret != "",
		"secret_expires_at", resp.ClientSecretExpiresAt,
		"token_endpoint_auth_method", resp.TokenEndpointAuthMethod,
		"scope", resp.Scope,
		"error", resp.Error,
		"error_description", resp.ErrorDescription,
	)
}

// debugLogOAuthEndpoints logs the resolved OAuth endpoint URLs.
func debugLogOAuthEndpoints(label string, eps oauthEndpoints, source string) {
	if !debugEnabled() {
		return
	}
	slog.Debug(label,
		"source", source,
		"authorization_endpoint", eps.AuthorizationEndpoint,
		"token_endpoint", eps.TokenEndpoint,
		"registration_endpoint", eps.RegistrationEndpoint,
	)
}

// debugLogMCPCall logs an outgoing MCP tool call at DEBUG level.
func debugLogMCPCall(backend, tool string, args map[string]any) {
	if !debugEnabled() {
		return
	}
	slog.Debug("keep: MCP→ tool call", "backend", backend, "tool", tool, "args", args)
}

// debugLogMCPResult logs an MCP tool result at DEBUG level.
// content is marshalled to JSON so structured payloads are readable.
func debugLogMCPResult(backend, tool string, isError bool, content any) {
	if !debugEnabled() {
		return
	}
	raw, _ := json.Marshal(content)
	slog.Debug("keep: MCP← tool result", "backend", backend, "tool", tool, "is_error", isError, "content", string(raw))
}

// decodeJWTPart base64url-decodes a JWT segment and unmarshals it as JSON.
func decodeJWTPart(s string) (map[string]any, error) {
	// Add padding if needed.
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	raw, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		// Try without padding.
		raw, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}
	return m, nil
}

// toFloat64 coerces a JSON number (float64 or json.Number) to float64.
func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}
