package keep

import (
	"context"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// WorkflowHandler submits an escalation request to an enterprise workflow system.
// escalationJWT is a Keep-signed JWT encoding the full escalation context; plugins
// may embed it in approval URLs, ticket descriptions, or webhook payloads.
// The returned reference is workflow-specific: an approval URL, ticket ID, etc.
type WorkflowHandler interface {
	Submit(ctx context.Context, req shared.EnrichedMCPRequest, escalationJWT string) (reference string, err error)
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

func (n *noopWorkflow) Submit(_ context.Context, _ shared.EnrichedMCPRequest, _ string) (string, error) {
	return "", nil
}
