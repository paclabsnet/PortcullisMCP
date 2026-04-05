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
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SingleTenantProvider implements TenancyProvider for single-tenant deployments.
// It enables all Gate capabilities and falls through to server.go's existing
// buildDenyMessage / buildEscalationMessage logic for policy errors.
type SingleTenantProvider struct {
	id          IdentitySource
	tokenHeader string
}

// NewSingleTenantProvider creates a SingleTenantProvider. id may be nil if no
// OS/OIDC identity source is configured (e.g. token is always supplied via header).
func NewSingleTenantProvider(id IdentitySource, tokenHeader string) *SingleTenantProvider {
	return &SingleTenantProvider{id: id, tokenHeader: tokenHeader}
}

// Authenticate extracts the raw token from the configured header, falling back
// to the IdentitySource when no header token is present.
func (p *SingleTenantProvider) Authenticate(r *http.Request) (string, string, error) {
	rawToken := ""
	if p.tokenHeader != "" {
		rawToken = r.Header.Get(p.tokenHeader)
	}
	if rawToken == "" && p.id != nil {
		rawToken = p.id.Get(r.Context()).RawToken
	}
	sessionID := r.Header.Get("Mcp-Session-Id")
	return rawToken, sessionID, nil
}

// Capabilities returns the full set of Gate features for single-tenant mode.
func (p *SingleTenantProvider) Capabilities() Capabilities {
	return Capabilities{
		AllowLocalFS:      true,
		AllowManagementUI: true,
		AllowGuardPeer:    true,
		AllowHumanInLoop:  true,
		AllowNativeTools:  true,
	}
}

// MapPolicyError returns (nil, false) so that the caller falls through to the
// existing single-tenant policy-error logic in server.go.
func (p *SingleTenantProvider) MapPolicyError(_ context.Context, _ error, _, _ string, _ *Config) (*mcp.CallToolResult, bool) {
	return nil, false
}
