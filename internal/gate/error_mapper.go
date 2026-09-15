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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

const defaultRequireApprovalInstructions = "Escalation required: {reason}\n\nPresent this complete URL to the user so they can click it to approve the request. Do not truncate or shorten the URL:\n{url}\n\nTrace ID: {trace_id}"
const defaultDenyInstructions = "Access denied: {reason}\n\nIf you believe this is incorrect, contact your security team and reference trace ID: {trace_id}"

func (g *Gate) buildDenyMessage(reason, traceID string) string {
	instructions := g.cfg.Responsibility.AgentInteraction.Instructions.Deny
	if instructions == "" {
		instructions = defaultDenyInstructions
	}
	msg := strings.ReplaceAll(instructions, "{reason}", reason)
	msg = strings.ReplaceAll(msg, "{trace_id}", traceID)
	return msg
}

func (g *Gate) buildEscalationMessage(e *shared.EscalationPendingError, traceID string) string {
	guardEndpoint := g.cfg.Peers.Guard.Endpoints.ApprovalUI

	var approvalURL string
	if guardEndpoint != "" && e.EscalationJTI != "" {
		approvalURL = guardEndpoint + "/approve?jti=" + url.QueryEscape(e.EscalationJTI)
	}
	if approvalURL == "" && e.Reference != "" {
		approvalURL = e.Reference
	}

	if approvalURL == "" {
		slog.Warn("escalation required but no approval URL available", "reason", e.Reason)
		msg := "Escalation required: " + e.Reason
		if msg != "" {
			msg += "\n\nNo approval URL is available. The system may be misconfigured. Please contact your administrator."
		}
		return msg
	}

	instructions := g.cfg.Responsibility.AgentInteraction.Instructions.RequireApproval
	if instructions == "" {
		instructions = defaultRequireApprovalInstructions
	}

	msg := strings.ReplaceAll(instructions, "{reason}", e.Reason)
	msg = strings.ReplaceAll(msg, "{url}", approvalURL)
	msg = strings.ReplaceAll(msg, "{trace_id}", traceID)
	return msg
}

// enrichBackendAuthChallenge checks whether result is an error CallToolResult
// whose content contains a WWW-Authenticate header from a backend HTTP response.
// If so, it replaces the raw header dump with a structured, agent-friendly
// message that names the backend, explains the auth challenge, and tells the
// agent what to do.
func (g *Gate) enrichBackendAuthChallenge(result *mcp.CallToolResult, serverName, toolName string) *mcp.CallToolResult {
	if len(result.Content) == 0 {
		return result
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || text.Text == "" {
		return result
	}
	var wwwAuth string
	for _, line := range strings.Split(text.Text, "\n") {
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:idx]), "www-authenticate") {
			wwwAuth = strings.TrimSpace(line[idx+1:])
			break
		}
	}
	if wwwAuth == "" {
		return result
	}
	msg := fmt.Sprintf(
		"Authentication required to call tool %q on backend %q.\n\n"+
			"The backend issued an authentication challenge:\n"+
			"  WWW-Authenticate: %s\n\n"+
			"Obtain a valid credential for the %q backend and ensure it is "+
			"configured in your Gate identity settings, or contact your administrator.",
		toolName, serverName, wwwAuth, serverName,
	)
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}

func (g *Gate) policyErrToResult(ctx context.Context, err error, toolName, traceID string) (*mcp.CallToolResult, error) {
	var escalationErr *shared.EscalationPendingError
	var denyErr *shared.DenyError
	var identityErr *shared.IdentityVerificationError
	var guardUnavailableErr *GuardUnavailableError

	// When escalation is disabled, intercept EscalationPendingError: emit a SIEM
	// log and return the configured marker instead of the Guard approval URL.
	if g.cfg.Escalation == "disabled" && errors.As(err, &escalationErr) {
		if g.logger != nil {
			sid, _ := SessionIDFromContext(ctx)
			g.logger.Log(DecisionLogEntry{
				Timestamp: time.Now().UTC(),
				SessionID: sid,
				TraceID:   traceID,
				ToolName:  toolName,
				Decision:  "deny",
				Reason:    "escalation disabled: escalation intercepted",
				Source:    "gate-policy",
			})
		}
		marker := g.cfg.Responsibility.Escalation.NoEscalationMarker
		if marker == "" {
			marker = "Access denied."
		}
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: marker}},
		}, nil
	}

	switch {
	case errors.As(err, &escalationErr):
		effectiveTraceID := escalationErr.TraceID
		if effectiveTraceID == "" {
			effectiveTraceID = traceID
		}
		if g.cfg.Peers.Guard.resolvedAPIEndpoint() == "" {
			slog.Warn("escalation required but Guard is not configured", "tool", toolName, "reason", escalationErr.Reason)
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: g.buildDenyMessage(escalationErr.Reason, effectiveTraceID)}},
			}, nil
		}
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: g.buildEscalationMessage(escalationErr, effectiveTraceID)}},
		}, nil
	case errors.As(err, &denyErr):
		effectiveTraceID := denyErr.TraceID
		if effectiveTraceID == "" {
			effectiveTraceID = traceID
		}
		if g.logger != nil {
			sid, _ := SessionIDFromContext(ctx)
			g.logger.Log(DecisionLogEntry{
				Timestamp: time.Now().UTC(),
				SessionID: sid,
				TraceID:   effectiveTraceID,
				ToolName:  toolName,
				Decision:  "deny",
				Reason:    denyErr.Reason,
				Source:    "gate-policy",
			})
		}
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: g.buildDenyMessage(denyErr.Reason, effectiveTraceID)}},
		}, nil
	case errors.As(err, &identityErr):
		slog.Warn("identity verification failed", "error", identityErr.Reason, "trace_id", traceID)
		if g.cfg.Identity.Strategy == "oidc-login" {
			g.stateMachine.SetUnauthenticated()
			g.identity.Clear()
			loginMsg := g.handleLoginTool(ctx, false)
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: "Your authentication has expired. " + loginMsg}},
			}, nil
		}
		return nil, err
	case errors.Is(err, shared.ErrDenied):
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: g.buildDenyMessage("", traceID)}},
		}, nil
	case errors.As(err, &guardUnavailableErr):
		slog.Error("guard unavailable during escalation", "jti", guardUnavailableErr.JTI, "error", guardUnavailableErr.Err, "tool", toolName)
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "Authorization system unavailable. Please try again later or contact your administrator."}},
		}, nil
	}
	slog.Error("keep call failed", "error", err, "tool", toolName, "request_id", traceID)
	return nil, err
}
