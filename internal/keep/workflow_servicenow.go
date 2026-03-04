package keep

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

type serviceNowHandler struct {
	instance string
	creds    string
	client   *http.Client
}

func newServiceNowHandler(cfg ServiceNowConfig) (*serviceNowHandler, error) {
	if cfg.Instance == "" {
		return nil, fmt.Errorf("servicenow: instance is required")
	}
	creds := os.Getenv(cfg.CredentialEnv)
	if creds == "" {
		return nil, fmt.Errorf("servicenow: credential env %q is not set", cfg.CredentialEnv)
	}
	return &serviceNowHandler{
		instance: cfg.Instance,
		creds:    creds,
		client:   &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// Submit opens a ServiceNow change request for the escalation.
// The change request description includes the tool call details and the PDP
// reason. The approver is expected to send a signed JWT to the user out-of-band.
func (h *serviceNowHandler) Submit(ctx context.Context, req shared.EnrichedMCPRequest, pdpReason string) (string, error) {
	body := map[string]any{
		"short_description": fmt.Sprintf(
			"Portcullis escalation: %s/%s requested by %s",
			req.ServerName, req.ToolName, req.UserIdentity.UserID,
		),
		"description": fmt.Sprintf(
			"Tool: %s\nServer: %s\nUser: %s (%s)\nReason: %s\nRequest ID: %s\nSession ID: %s",
			req.ToolName, req.ServerName,
			req.UserIdentity.DisplayName, req.UserIdentity.UserID,
			pdpReason, req.RequestID, req.SessionID,
		),
		"caller_id":  req.UserIdentity.UserID,
		"category":   "AI Agent Access Request",
		"assignment": "Portcullis Approvers",
	}

	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("servicenow: marshal request: %w", err)
	}

	url := fmt.Sprintf("https://%s/api/now/table/change_request", h.instance)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("servicenow: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", "Basic "+h.creds)

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("servicenow: post change request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("servicenow: unexpected status %d", resp.StatusCode)
	}

	var result struct {
		Result struct {
			SysID  string `json:"sys_id"`
			Number string `json:"number"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("servicenow: decode response: %w", err)
	}
	return result.Result.Number, nil
}
