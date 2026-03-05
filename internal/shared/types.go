package shared

import "errors"

// UserIdentity carries the resolved identity of the local user.
// SourceType indicates how the identity was obtained; "os" is provided for
// testing/evaluation only — portcullis-keep may be configured to reject it.
type UserIdentity struct {
	UserID      string   `json:"user_id"`      // stable enterprise identifier (UPN, email, etc.)
	DisplayName string   `json:"display_name"`
	Groups      []string `json:"groups"`       // for PDP group-based policy
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
	RequestID        string            `json:"request_id"`
}

// PDPResponse is the decision returned by the Policy Decision Point.
type PDPResponse struct {
	Decision  string `json:"decision"`             // "allow" | "deny" | "escalate"
	Reason    string `json:"reason"`
	RequestID string `json:"request_id,omitempty"` // echoed from the input request, if the PDP chooses to include it
}

// Sentinel errors for known failure modes.
var (
	ErrDenied            = errors.New("portcullis: request denied by policy")
	ErrEscalationPending = errors.New("portcullis: escalation pending approval")
	ErrPDPUnavailable    = errors.New("portcullis: policy decision point unavailable")
)
