package keep

import (
	"context"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// WorkflowHandler submits an escalation request to an enterprise workflow system.
// The call returns a workflow-specific request ID that can be used for tracking.
// Escalation is async: portcullis-keep does not wait for approval.
type WorkflowHandler interface {
	Submit(ctx context.Context, req shared.EnrichedMCPRequest, pdpReason string) (requestID string, err error)
}

// NewWorkflowHandler creates the appropriate WorkflowHandler from config.
func NewWorkflowHandler(cfg WorkflowConfig) (WorkflowHandler, error) {
	switch cfg.Type {
	case "servicenow":
		return newServiceNowHandler(cfg.ServiceNow)
	case "webhook":
		return newWebhookHandler(cfg.Webhook)
	default:
		return &noopWorkflow{}, nil
	}
}

// noopWorkflow is used when no workflow system is configured.
type noopWorkflow struct{}

func (n *noopWorkflow) Submit(_ context.Context, _ shared.EnrichedMCPRequest, _ string) (string, error) {
	return "", nil
}
