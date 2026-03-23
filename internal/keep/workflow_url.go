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
	"context"
	"fmt"
	"net/url"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// urlWorkflowHandler is the demo workflow plugin.
// It builds a Guard approval URL containing the escalation request JWT and
// returns it as the reference, which Keep surfaces to the agent via the MCP
// error channel so the user can click through and approve.
type urlWorkflowHandler struct {
	guardURL string
}

func newURLWorkflowHandler(cfg URLWorkflowConfig) (*urlWorkflowHandler, error) {
	if cfg.GuardURL == "" {
		return nil, fmt.Errorf("url workflow: guard_url is required")
	}
	return &urlWorkflowHandler{guardURL: cfg.GuardURL}, nil
}

// Submit returns a Guard approval URL as the workflow reference.
// The escalationJWT must be non-empty; if it is, the URL plugin cannot function.
func (h *urlWorkflowHandler) Submit(_ context.Context, _ shared.EnrichedMCPRequest, escalationJWT string) (string, error) {
	if escalationJWT == "" {
		return "", fmt.Errorf("url workflow: escalation JWT is required (configure keep.signing.key)")
	}
	return fmt.Sprintf("%s/approve?token=%s", h.guardURL, url.QueryEscape(escalationJWT)), nil
}
