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

// TenancyProvider abstracts the behavioural differences between single-tenant
// and multi-tenant deployments of the Gate.
type TenancyProvider interface {
	// Authenticate extracts the user's identity and maps it to a session.
	Authenticate(r *http.Request) (rawToken, sessionID string, err error)

	// Capabilities returns the feature flags allowed for this tenancy mode.
	Capabilities() Capabilities

	// MapPolicyError converts internal policy results into MCP Tool results.
	// It returns (result, handled). If handled=true, the caller should return
	// the result immediately.
	MapPolicyError(ctx context.Context, err error, tool, traceID string, cfg *Config) (*mcp.CallToolResult, bool)
}

// Capabilities describes which Gate features are enabled for a given tenancy mode.
type Capabilities struct {
	AllowLocalFS      bool
	AllowManagementUI bool
	AllowGuardPeer    bool
	AllowHumanInLoop  bool
	AllowNativeTools  bool
}
