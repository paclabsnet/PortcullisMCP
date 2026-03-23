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

package shared

import (
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// LocalFSServerName is the agreed server name used when gate sends local filesystem
// tool calls to Keep for policy authorization. Keep evaluates the PDP but does not
// execute the tool — gate executes it locally via its in-process filesystem session.
const LocalFSServerName = "portcullis-localfs"

// AnnotatedTool pairs an MCP tool schema with the backend server name it belongs to.
// The server name is used by portcullis-gate to route tool calls to the correct backend.
type AnnotatedTool struct {
	ServerName string    `json:"server_name"`
	Tool       *mcp.Tool `json:"tool"`
}

// UserIdentity carries the resolved identity of the local user.
// SourceType indicates how the identity was obtained; "os" is provided for
// testing/evaluation only — portcullis-keep may be configured to reject it.
type UserIdentity struct {
	UserID      string   `json:"user_id"`      // stable enterprise identifier (UPN, email, etc.)
	Email       string   `json:"email,omitempty"`
	DisplayName string   `json:"display_name"`
	Groups      []string `json:"groups"`       // directory groups
	Roles       []string `json:"roles,omitempty"`      // RBAC roles, distinct from directory groups
	Department  string   `json:"department,omitempty"` // org unit / department for ABAC
	AuthMethod  []string `json:"auth_method,omitempty"` // OIDC AMR claim, e.g. ["pwd","mfa"]
	TokenExpiry int64    `json:"token_expiry,omitempty"` // Unix timestamp; 0 means unknown
	SourceType  string   `json:"source_type"`  // "oidc" | "os"
	RawToken    string   `json:"raw_token"`    // original OIDC token for PDP verification
}

// EscalationToken is a pre-authorization JWT the user received out-of-band.
// portcullis-gate does not evaluate the token itself — the PDP does.
type EscalationToken struct {
	TokenID   string `json:"token_id"`
	Raw       string `json:"raw"`        // signed JWT as received
	GrantedBy string `json:"granted_by"` // display name of approver
}

// EnrichedMCPRequest is the payload portcullis-gate sends to portcullis-keep
// for every tool call that is not handled by the local fast-path.
type EnrichedMCPRequest struct {
	ServerName       string            `json:"server_name"`
	ToolName         string            `json:"tool_name"`
	Arguments        map[string]any    `json:"arguments"`
	UserIdentity     UserIdentity      `json:"user_identity"`
	EscalationTokens []EscalationToken `json:"escalation_tokens"`
	SessionID        string            `json:"session_id"`
	// TraceID is the single correlation identifier for this request.
	// When OTel telemetry is enabled it is the W3C trace ID from the active span.
	// When telemetry is disabled (noop exporter) Gate generates a UUID so this
	// field is always non-empty and can be used for log correlation and deny messages.
	TraceID string `json:"trace_id"`
}

// PDPResponse is the decision returned by the Policy Decision Point.
type PDPResponse struct {
	Decision        string         `json:"decision"`                   // "allow" | "deny" | "escalate"
	Reason          string         `json:"reason"`
	EscalationScope []map[string]any `json:"escalation_scope,omitempty"` // claims required for escalation token
	RequestID       string         `json:"request_id,omitempty"`       // echoed from the input request, if the PDP chooses to include it
}

// EscalationPendingError is returned when the PDP requires escalation approval.
// Reference is a workflow-specific identifier — an approval URL, ticket ID, etc.
// EscalationJTI is the JWT ID of the pending escalation request, used by Gate
// to track and later claim the approved token from Guard.
type EscalationPendingError struct {
	Reason        string
	Reference     string
	EscalationJTI string
}

func (e *EscalationPendingError) Error() string {
	msg := "Escalation required"
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	if e.Reference != "" {
		msg += "\n\nPresent this complete URL to the user so they can click it to approve the request. Do not truncate or shorten the URL:\n" + e.Reference
	}
	return msg
}

func (e *EscalationPendingError) Unwrap() error { return ErrEscalationPending }

// Sentinel errors for known failure modes.
var (
	ErrDenied            = errors.New("portcullis: request denied by policy")
	ErrEscalationPending = errors.New("portcullis: escalation pending approval")
	ErrPDPUnavailable    = errors.New("portcullis: policy decision point unavailable")
)
