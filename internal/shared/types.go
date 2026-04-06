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

// ServiceGate is the canonical name for the portcullis-gate component.
// Used as the MCP implementation name, OTel tracer name, and log identifier.
const ServiceGate = "portcullis-gate"

// ServiceKeep is the canonical name for the portcullis-keep component.
// Used as the JWT issuer for escalation request JWTs, the MCP implementation
// name, OTel tracer name, and log identifier.
const ServiceKeep = "portcullis-keep"

// ServiceGuard is the canonical name for the portcullis-guard component.
// Used as the JWT issuer for escalation token JWTs, the OTel tracer name,
// and log identifier.
const ServiceGuard = "portcullis-guard"

// LocalFSServerName is the agreed server name used when gate sends local filesystem
// tool calls to Keep for policy authorization. Keep evaluates the PDP but does not
// execute the tool — gate executes it locally via its in-process filesystem session.
const LocalFSServerName = "portcullis-localfs"

// APIVersion is the current version of the Gate→Keep request protocol.
// Gate sets this on every EnrichedMCPRequest; Keep rejects requests that
// carry an unrecognised non-empty version so that mismatched deployments
// fail loudly rather than silently misinterpreting request fields.
// Increment this constant — and handle or reject the previous value in Keep —
// whenever a breaking change is made to EnrichedMCPRequest.
const APIVersion = "1"

// AnnotatedTool pairs an MCP tool schema with the backend server name it belongs to.
// The server name is used by portcullis-gate to route tool calls to the correct backend.
type AnnotatedTool struct {
	ServerName string    `json:"server_name"`
	Tool       *mcp.Tool `json:"tool"`
}

// UserIdentity carries the resolved identity of the local user as claimed by Gate.
// SourceType indicates how the identity was obtained; "os" is provided for
// testing/evaluation only — portcullis-keep may be configured to reject it.
type UserIdentity struct {
	UserID            string   `json:"user_id"` // stable enterprise identifier (UPN, email, etc.)
	Email             string   `json:"email,omitempty"`
	DisplayName       string   `json:"display_name"`
	Groups            []string `json:"groups"`                       // directory groups
	Roles             []string `json:"roles,omitempty"`              // RBAC roles, distinct from directory groups
	Department        string   `json:"department,omitempty"`         // org unit / department for ABAC
	AuthMethod        []string `json:"auth_method,omitempty"`        // OIDC AMR claim, e.g. ["pwd","mfa"]
	PreferredUsername string   `json:"preferred_username,omitempty"` // human-readable login name (Azure AD / Okta UPN)
	ACR               string   `json:"acr,omitempty"`                // OIDC ACR claim, e.g. "mfa"
	TokenExpiry       int64    `json:"token_expiry,omitempty"`       // Unix timestamp; 0 means unknown
	SourceType        string   `json:"source_type"`                  // "oidc" | "os"
	RawToken          string   `json:"raw_token"`                    // original OIDC token for PDP verification
}

// Principal represents the verified facts about a user after Keep has performed
// identity normalization and validation. The PDP evaluates policies against
// the Principal, not the raw UserIdentity received from Gate.
type Principal struct {
	UserID            string   `json:"user_id"`
	Email             string   `json:"email,omitempty"`
	DisplayName       string   `json:"display_name,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Roles             []string `json:"roles,omitempty"`
	Department        string   `json:"department,omitempty"`
	AuthMethod        []string `json:"auth_method,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"` // human-readable login name (Azure AD / Okta UPN)
	ACR               string   `json:"acr,omitempty"`                // OIDC ACR claim, e.g. "mfa"
	TokenExpiry       int64    `json:"token_expiry,omitempty"`
	SourceType        string   `json:"source_type"`
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
	// APIVersion identifies the protocol version of this request.
	// Gate sets this to the APIVersion constant; Keep rejects requests with an
	// unrecognised non-empty value. Omitted by older Gate versions — Keep
	// accepts those for backward compatibility and treats them as version "1".
	APIVersion       string            `json:"api_version,omitempty"`
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
	// ClientHeaders are HTTP headers from the original client request to Gate.
	// Header names are in Canonical-Format (http.CanonicalHeaderKey). Values are
	// unmodified. Forbidden headers are never included regardless of configuration.
	ClientHeaders map[string][]string `json:"client_headers,omitempty"`
}

// PDPResponse is the decision returned by the Policy Decision Point.
type PDPResponse struct {
	Decision        string           `json:"decision"` // "allow" | "deny" | "escalate" | "workflow"
	Reason          string           `json:"reason"`
	EscalationScope []map[string]any `json:"escalation_scope,omitempty"` // claims required for escalation token
}

// EscalationPendingError is returned when the PDP requires escalation approval.
// Reference is a workflow-specific identifier — a ticket ID, external URL, etc.
// EscalationJTI is the JWT ID of the pending escalation request, used by Gate
// to track and later claim the approved token from Guard.
// PendingJWT is the raw Keep-signed escalation request JWT; Gate uses it to
// either build the approval URL (user-driven mode) or push it proactively to Guard.
// TraceID is the correlation ID Keep logged for this request; Gate surfaces it
// in the agent-facing message so users can quote it to the security team.
type EscalationPendingError struct {
	Reason        string
	Reference     string
	EscalationJTI string
	PendingJWT    string
	TraceID       string
}

// DenyError is returned when Keep denies a request. It carries the policy
// reason text and the trace ID so Gate can surface them in the agent-facing
// message. Unwraps to ErrDenied so existing errors.Is checks continue to work.
type DenyError struct {
	Reason  string
	TraceID string
}

// SessionUnknownError is returned when Keep no longer recognizes Gate's
// in-memory session (for example, after a Keep restart). Gate can use this to
// resync session state and retry the request.
type SessionUnknownError struct {
	SessionID string
	Reason    string
}

// IdentityVerificationError is returned when token verification fails, typically because
// the identity token is invalid or has expired (e.g., JWKS kid mismatch after IdP restart).
// Gate can use this error to prompt the user to provide a new identity rather than
// treating it as a PDP unavailability.
type IdentityVerificationError struct {
	Reason string
}

func (e *IdentityVerificationError) Error() string {
	if e.Reason != "" {
		return e.Reason
	}
	return ErrIdentityVerificationFailed.Error()
}

func (e *IdentityVerificationError) Unwrap() error { return ErrIdentityVerificationFailed }

func (e *DenyError) Error() string {
	if e.Reason != "" {
		return "portcullis: request denied by policy: " + e.Reason
	}
	return ErrDenied.Error()
}

func (e *DenyError) Unwrap() error { return ErrDenied }

func (e *SessionUnknownError) Error() string {
	if e.Reason != "" {
		return e.Reason
	}
	return ErrSessionUnknown.Error()
}

func (e *SessionUnknownError) Unwrap() error { return ErrSessionUnknown }

func (e *EscalationPendingError) Error() string {
	msg := "Escalation required"
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	return msg
}

func (e *EscalationPendingError) Unwrap() error { return ErrEscalationPending }

// Sentinel errors for known failure modes.
var (
	ErrDenied                     = errors.New("portcullis: request denied by policy")
	ErrEscalationPending          = errors.New("portcullis: escalation pending approval")
	ErrPDPUnavailable             = errors.New("portcullis: policy decision point unavailable")
	ErrSessionUnknown             = errors.New("portcullis: keep session unknown")
	ErrIdentityVerificationFailed = errors.New("portcullis: identity verification failed")
)
