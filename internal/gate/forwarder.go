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

package gate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// Forwarder sends enriched MCP requests to portcullis-keep and returns the result.
type Forwarder struct {
	auth   cfgloader.PeerAuth
	client *http.Client
}

// NewForwarder creates a Forwarder configured for the given Keep endpoint.
func NewForwarder(auth cfgloader.PeerAuth) (*Forwarder, error) {
	transport, err := buildTransport(auth)
	if err != nil {
		return nil, fmt.Errorf("build keep transport: %w", err)
	}
	return &Forwarder{
		auth:   auth,
		client: &http.Client{Transport: transport},
	}, nil
}

// CallTool forwards a tool call to Keep and returns the MCP result.
func (f *Forwarder) CallTool(ctx context.Context, req shared.EnrichedMCPRequest) (*mcp.CallToolResult, error) {
	var result mcp.CallToolResult
	if err := f.post(ctx, "/call", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Authorize asks Keep to evaluate the PDP for a gate-local tool call without
// executing the tool. Returns nil on allow, ErrDenied on deny,
// EscalationPendingError on escalate, or ErrPDPUnavailable if Keep is down.
func (f *Forwarder) Authorize(ctx context.Context, req shared.EnrichedMCPRequest) error {
	var resp shared.PDPResponse
	return f.post(ctx, "/authorize", req, &resp)
}

// ListTools fetches the annotated tool list from Keep.
// Each entry carries the backend server name alongside the tool schema,
// so the caller can build a routing map without guessing.
func (f *Forwarder) ListTools(ctx context.Context, identity shared.UserIdentity, escalationTokens []shared.EscalationToken) ([]shared.AnnotatedTool, error) {
	reqBody := struct {
		UserIdentity     shared.UserIdentity      `json:"user_identity"`
		EscalationTokens []shared.EscalationToken `json:"escalation_tokens"`
	}{
		UserIdentity:     identity,
		EscalationTokens: escalationTokens,
	}
	var tools []shared.AnnotatedTool
	if err := f.post(ctx, "/tools", reqBody, &tools); err != nil {
		return nil, err
	}
	return tools, nil
}

// SendLogs sends a batch of decision log entries to Keep.
// This is best-effort — errors are logged but not returned.
func (f *Forwarder) SendLogs(ctx context.Context, entries []DecisionLogEntry) error {
	if len(entries) == 0 {
		return nil
	}
	batch := struct {
		APIVersion string             `json:"api_version,omitempty"`
		Entries    []DecisionLogEntry `json:"entries"`
	}{
		APIVersion: shared.APIVersion,
		Entries:    entries,
	}
	var result map[string]interface{}
	return f.post(ctx, "/log", batch, &result)
}

// the core mechanism for sending messages to Keep, both the
// enriched MCP requests, and the locally-generated decision logs
func (f *Forwarder) post(ctx context.Context, path string, body, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.auth.Endpoint+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if f.auth.Auth.Type == "bearer" && f.auth.Auth.Credentials.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+f.auth.Auth.Credentials.BearerToken)
	}
	// Inject W3C TraceContext headers so Keep continues the same trace.
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("keep request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return json.NewDecoder(resp.Body).Decode(out)
	case http.StatusUnauthorized:
		// Identity verification failed (e.g., JWKS kid mismatch after IdP restart).
		// Gate should prompt the user to re-authenticate rather than treating this as PDP unavailability.
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return &shared.IdentityVerificationError{Reason: body.Error}
	case http.StatusForbidden:
		var body struct {
			Error   string `json:"error"`
			TraceID string `json:"trace_id"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return &shared.DenyError{Reason: body.Error, TraceID: body.TraceID}
	case http.StatusAccepted:
		var body struct {
			Reason        string `json:"reason"`
			Reference     string `json:"workflow_reference"`
			EscalationJTI string `json:"escalation_jti"`
			PendingJWT    string `json:"pending_jwt"`
			TraceID       string `json:"trace_id"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return &shared.EscalationPendingError{
			Reason:        body.Reason,
			Reference:     body.Reference,
			EscalationJTI: body.EscalationJTI,
			PendingJWT:    body.PendingJWT,
			TraceID:       body.TraceID,
		}
	case http.StatusServiceUnavailable:
		return shared.ErrPDPUnavailable
	default:
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return fmt.Errorf("keep returned %d: %s", resp.StatusCode, errBody.Error)
	}
}

// buildTransport constructs an http.RoundTripper based on the auth config.
func buildTransport(auth cfgloader.PeerAuth) (http.RoundTripper, error) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	if base.TLSClientConfig == nil {
		base.TLSClientConfig = &tls.Config{}
	}

	// Load a custom server CA for verifying Keep's TLS certificate.
	// Required when Keep uses a private or enterprise CA not in the system pool.
	if auth.Auth.Credentials.ServerCA != "" {
		caData, err := os.ReadFile(auth.Auth.Credentials.ServerCA)
		if err != nil {
			return nil, fmt.Errorf("read keep server CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("parse keep server CA: no valid certificates found")
		}
		base.TLSClientConfig.RootCAs = pool
	}

	if auth.Auth.Type == "mtls" {
		if auth.Auth.Credentials.Cert == "" || auth.Auth.Credentials.Key == "" {
			return nil, fmt.Errorf("mtls auth requires cert and key")
		}
		cert, err := tls.LoadX509KeyPair(auth.Auth.Credentials.Cert, auth.Auth.Credentials.Key)
		if err != nil {
			return nil, fmt.Errorf("load mtls keypair: %w", err)
		}
		base.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	return base, nil
}
