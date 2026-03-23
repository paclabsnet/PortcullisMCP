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
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	"github.com/paclabsnet/PortcullisMCP/internal/telemetry"
)

// PolicyDecisionPoint evaluates an enriched MCP request and returns a decision.
// Evaluation is performed against a normalized Principal.
type PolicyDecisionPoint interface {
	Evaluate(ctx context.Context, req shared.EnrichedMCPRequest, p shared.Principal) (shared.PDPResponse, error)
}

// noopPDP is a PolicyDecisionPoint that allows every request unconditionally.
// It is intended for local evaluation and getting-started scenarios only.
// Do not use in production — it provides no access control whatsoever.
type noopPDP struct{}

// NewNoopPDPClient returns a PolicyDecisionPoint that allows all requests.
// A warning is logged at startup to make clear that policy enforcement is disabled.
func NewNoopPDPClient() PolicyDecisionPoint {
	slog.Warn("keep: PDP type is \"noop\" — all requests will be allowed without policy evaluation; do not use in production")
	return &noopPDP{}
}

func (n *noopPDP) Evaluate(_ context.Context, _ shared.EnrichedMCPRequest, _ shared.Principal) (shared.PDPResponse, error) {
	return shared.PDPResponse{
		Decision: "allow",
		Reason:   "noop pdp: policy enforcement disabled",
	}, nil
}

// opaClient calls the OPA REST API to evaluate policy.
type opaClient struct {
	endpoint string
	client   *http.Client
}

// NewOPAClient creates a PolicyDecisionPoint backed by an OPA REST endpoint.
// endpoint should be the full URL to the OPA data path, e.g.:
//
//	http://opa.internal:8181/v1/data/portcullis/decision
func NewOPAClient(endpoint string) PolicyDecisionPoint {
	return &opaClient{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// opaRequest is the envelope OPA expects: {"input": <payload>}.
type opaRequest struct {
	Input opaInput `json:"input"`
}

type opaInput struct {
	AuthorizationRequest opaAuthzRequest `json:"authorization_request"`
	SessionID            string          `json:"session_id"`
	RequestID            string          `json:"request_id"`
}

type opaAuthzRequest struct {
	Action    opaAction    `json:"action"`
	Resource  opaResource  `json:"resource"`
	Principal opaPrincipal `json:"principal"`
	Context   opaContext   `json:"context"`
}

type opaAction struct {
	Service  string `json:"service"`
	ToolName string `json:"tool_name"`
}

type opaResource struct {
	Arguments map[string]any `json:"arguments,omitempty"`
}

// parsedURL holds a normalized, structured breakdown of a URL for easy policy authoring.
// The path is cleaned to prevent traversal attacks before being sent to the PDP.
type parsedURL struct {
	Raw    string `json:"raw"`             // normalized form after parsing
	Scheme string `json:"scheme"`          // e.g. "https"
	Host   string `json:"host"`            // hostname without port
	Port   string `json:"port,omitempty"`  // empty when using scheme default
	Path   string `json:"path"`            // cleaned path, never contains ".."
	Query  string `json:"query,omitempty"` // raw query string
}

// urlFromArgs extracts a URL string from tool arguments, checking common key
// names used by HTTP MCP servers ("url", "uri").  Returns "" and "" if not found.
func urlFromArgs(args map[string]any) (string, string) {
	for _, key := range []string{"url", "uri"} {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok {
				return s, key
			}
		}
	}
	return "", ""
}

// parseAndNormalizeURL parses rawURL and returns a structured, normalized form.
// The path is cleaned via path.Clean to eliminate any ".." traversal segments.
// Returns nil if rawURL is empty or cannot be parsed.
func parseAndNormalizeURL(rawURL string) *parsedURL {
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	u.Path = path.Clean(u.Path)
	return &parsedURL{
		Raw:    u.String(),
		Scheme: u.Scheme,
		Host:   u.Hostname(),
		Port:   u.Port(),
		Path:   u.Path,
		Query:  u.RawQuery,
	}
}

// expandURLArgs returns a copy of args where any "url" or "uri" key is replaced
// by the structured, normalized URL parts (raw, scheme, host, port, path, query).
// Non-URL keys are preserved unchanged. If no URL key is found, args is returned as-is.
func expandURLArgs(args map[string]any) map[string]any {
	rawURL, urlKey := urlFromArgs(args)
	parsed := parseAndNormalizeURL(rawURL)
	if parsed == nil {
		return args
	}
	result := make(map[string]any, len(args)+5)
	for k, v := range args {
		if k != urlKey {
			result[k] = v
		}
	}
	result["raw"] = parsed.Raw
	result["scheme"] = parsed.Scheme
	result["host"] = parsed.Host
	result["port"] = parsed.Port
	result["path"] = parsed.Path
	result["query"] = parsed.Query
	return result
}

type opaPrincipal struct {
	UserID      string   `json:"user_id"`
	Email       string   `json:"email,omitempty"`
	DisplayName string   `json:"display_name"`
	Groups      []string `json:"groups"`
	Roles       []string `json:"roles,omitempty"`
	Department  string   `json:"department,omitempty"`
	AuthMethod  []string `json:"auth_method,omitempty"`
	TokenExpiry int64    `json:"token_expiry,omitempty"`
	SourceType  string   `json:"source_type,omitempty"`
}

type opaContext struct {
	EscalationTokens []shared.EscalationToken `json:"escalation_tokens"`
}

// opaResponse is the envelope OPA returns: {"result": <decision>}.
type opaResponse struct {
	Result struct {
		Decision        string           `json:"decision"`
		Reason          string           `json:"reason"`
		RequestID       string           `json:"request_id"`       // optionally echoed by the PDP
		EscalationScope []map[string]any `json:"escalation_scope"` // claims required for escalation token
	} `json:"result"`
}

// Evaluate sends the enriched request to OPA and returns the PDP decision.
func (c *opaClient) Evaluate(ctx context.Context, req shared.EnrichedMCPRequest, p shared.Principal) (shared.PDPResponse, error) {
	ctx, span := otel.Tracer("portcullis-keep").Start(ctx, "keep.pdp.evaluate")
	defer span.End()
	span.SetAttributes(
		attribute.String("pdp.type", "opa"),
		attribute.String("pdp.endpoint", c.endpoint),
		attribute.String("trace.id", req.TraceID),
		attribute.String("tool.name", req.ToolName),
	)
	traceID := telemetry.TraceIDFromContext(ctx)

	body, err := json.Marshal(opaRequest{
		Input: opaInput{
			AuthorizationRequest: opaAuthzRequest{
				Action: opaAction{
					Service:  req.ServerName,
					ToolName: req.ToolName,
				},
				Resource: opaResource{
					Arguments: expandURLArgs(req.Arguments),
				},
				Principal: opaPrincipal{
					UserID:      p.UserID,
					Email:       p.Email,
					DisplayName: p.DisplayName,
					Groups:      p.Groups,
					Roles:       p.Roles,
					Department:  p.Department,
					AuthMethod:  p.AuthMethod,
					TokenExpiry: p.TokenExpiry,
					SourceType:  p.SourceType,
				},
				Context: opaContext{
					EscalationTokens: req.EscalationTokens,
				},
			},
			SessionID: req.SessionID,
			RequestID: req.TraceID, // OPA receives trace_id as the correlation ID
		},
	})
	if err != nil {
		return shared.PDPResponse{}, fmt.Errorf("marshal opa request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return shared.PDPResponse{}, fmt.Errorf("build opa request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Propagate W3C TraceContext so OPA decision logs are correlatable.
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(httpReq.Header))

	resp, err := c.client.Do(httpReq)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		slog.ErrorContext(ctx, "keep: opa request failed", "error", err, "trace_id", traceID)
		return shared.PDPResponse{}, fmt.Errorf("%w: %s", shared.ErrPDPUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		span.SetStatus(codes.Error, fmt.Sprintf("opa returned %d", resp.StatusCode))
		return shared.PDPResponse{}, fmt.Errorf("%w: opa returned %d", shared.ErrPDPUnavailable, resp.StatusCode)
	}

	var opaResp opaResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return shared.PDPResponse{}, fmt.Errorf("decode opa response: %w", err)
	}

	decision := opaResp.Result.Decision
	if decision == "" {
		// OPA returned an empty result — treat as deny (safe default).
		decision = "deny"
	}

	span.SetAttributes(attribute.String("pdp.decision", decision))
	slog.InfoContext(ctx, "keep: pdp decision", "decision", decision, "trace_id", traceID)

	return shared.PDPResponse{
		Decision:        decision,
		Reason:          opaResp.Result.Reason,
		RequestID:       opaResp.Result.RequestID,
		EscalationScope: opaResp.Result.EscalationScope,
	}, nil
}
