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
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// AuthorizedRequest represents an MCP request that has passed the security
// perimeter of portcullis-keep. It contains the original request context but
// replaces the raw UserIdentity claim with a verified Principal.
//
// Logic within Keep (PDP, Workflows, Signers) should only ever operate on
// an AuthorizedRequest to ensure they are using verified identity facts.
type AuthorizedRequest struct {
	ServerName       string
	ToolName         string
	Arguments        map[string]any
	SessionID        string
	TraceID          string
	EscalationTokens []shared.EscalationToken
	Principal        shared.Principal
	// ClientHeaders are the HTTP request headers forwarded by Gate.
	// Header names are in Canonical-Format. The PDP receives these so that
	// policies can make decisions based on client identity headers (e.g.
	// X-Tenant-Id, Authorization) without requiring a separate token exchange.
	ClientHeaders map[string][]string
}

// NewAuthorizedRequest constructs a trusted internal request from a raw inbound
// request and a verified principal.
func NewAuthorizedRequest(req shared.EnrichedMCPRequest, p shared.Principal) AuthorizedRequest {
	return AuthorizedRequest{
		ServerName:       req.ServerName,
		ToolName:         req.ToolName,
		Arguments:        req.Arguments,
		SessionID:        req.SessionID,
		TraceID:          req.TraceID,
		EscalationTokens: req.EscalationTokens,
		Principal:        p,
		ClientHeaders:    req.ClientHeaders,
	}
}
