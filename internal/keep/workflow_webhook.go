package keep

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

type webhookHandler struct {
	cfg    WebhookConfig
	client *http.Client
}

func newWebhookHandler(cfg WebhookConfig) (*webhookHandler, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("webhook: url is required")
	}
	return &webhookHandler{
		cfg:    cfg,
		client: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// Submit POSTs the escalation payload to the configured webhook URL.
// The approver is expected to send a signed JWT to the user out-of-band.
func (h *webhookHandler) Submit(ctx context.Context, req shared.EnrichedMCPRequest, pdpReason string) (string, error) {
	payload := map[string]any{
		"request_id": req.RequestID,
		"session_id": req.SessionID,
		"server":     req.ServerName,
		"tool":       req.ToolName,
		"arguments":  req.Arguments,
		"user": map[string]any{
			"id":          req.UserIdentity.UserID,
			"display":     req.UserIdentity.DisplayName,
			"groups":      req.UserIdentity.Groups,
			"source_type": req.UserIdentity.SourceType,
		},
		"pdp_reason": pdpReason,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("webhook: marshal payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.cfg.URL, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("webhook: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range h.cfg.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("webhook: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("webhook: unexpected status %d", resp.StatusCode)
	}

	// Optionally parse a request ID from the webhook response.
	var result struct {
		RequestID string `json:"request_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if result.RequestID != "" {
		return result.RequestID, nil
	}
	return req.RequestID, nil
}
