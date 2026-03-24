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

// Submit returns an empty workflow reference. Gate is now responsible for
// building the approval URL using the escalation_jti or escalation_jwt fields
// from the 202 response, depending on its approval_management_strategy config.
// The guard_url is retained in the config for future use (e.g. ServiceNow
// redirect or display purposes) but is no longer embedded in a query string.
func (h *urlWorkflowHandler) Submit(_ context.Context, _ AuthorizedRequest, _ string) (string, error) {
	return "", nil
}
