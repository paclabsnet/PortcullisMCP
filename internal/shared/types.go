package shared

import "errors"

// UserIdentity carries the resolved identity of the local user.
// SourceType indicates how the identity was obtained; "os" is provided for
// testing/evaluation only — portcullis-keep may be configured to reject it.
type UserIdentity struct {
	UserID      string // stable enterprise identifier (UPN, email, etc.)
	DisplayName string
	Groups      []string // for PDP group-based policy
	SourceType  string   // "oidc" | "os"
	RawToken    string   // original OIDC token for PDP verification
}

// EscalationToken is a pre-authorization JWT the user received out-of-band.
// portcullis-gate does not evaluate the token itself — the PDP does.
type EscalationToken struct {
	TokenID   string
	Raw       string // signed JWT as received
	GrantedBy string // display name of approver
}

// EnrichedMCPRequest is the payload portcullis-gate sends to portcullis-keep
// for every tool call that is not handled by the local fast-path.
type EnrichedMCPRequest struct {
	ServerName       string
	ToolName         string
	Arguments        map[string]any
	UserIdentity     UserIdentity
	EscalationTokens []EscalationToken
	SessionID        string
	RequestID        string // gate-generated UUID per call
}

// PDPResponse is the decision returned by the Policy Decision Point.
type PDPResponse struct {
	Decision string // "allow" | "deny" | "escalate"
	Reason   string
}

// Sentinel errors for known failure modes.
var (
	ErrDenied            = errors.New("portcullis: request denied by policy")
	ErrEscalationPending = errors.New("portcullis: escalation pending approval")
	ErrPDPUnavailable    = errors.New("portcullis: policy decision point unavailable")
)
