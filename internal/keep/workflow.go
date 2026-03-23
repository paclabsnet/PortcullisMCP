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
)

// WorkflowHandler submits an escalation request to an enterprise workflow system.
// escalationJWT is a Keep-signed JWT encoding the full escalation context; plugins
// may embed it in approval URLs, ticket descriptions, or webhook payloads.
// The returned reference is workflow-specific: an approval URL, ticket ID, etc.
type WorkflowHandler interface {
	Submit(ctx context.Context, req AuthorizedRequest, escalationJWT string) (reference string, err error)
}

// NewWorkflowHandler creates the appropriate WorkflowHandler from config.
func NewWorkflowHandler(cfg WorkflowConfig) (WorkflowHandler, error) {
	switch cfg.Type {
	case "servicenow":
		return newServiceNowHandler(cfg.ServiceNow)
	case "webhook":
		return newWebhookHandler(cfg.Webhook)
	case "url":
		return newURLWorkflowHandler(cfg.URL)
	default:
		return &noopWorkflow{}, nil
	}
}

// noopWorkflow is used when no workflow system is configured.
type noopWorkflow struct{}

func (n *noopWorkflow) Submit(_ context.Context, _ AuthorizedRequest, _ string) (string, error) {
	return "", nil
}
