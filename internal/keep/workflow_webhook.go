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
// The escalationJWT is included so the webhook handler can build approval URLs
// or forward the token to the user via the enterprise's own notification system.
func (h *webhookHandler) Submit(ctx context.Context, req shared.EnrichedMCPRequest, escalationJWT string) (string, error) {
	payload := map[string]any{
		"trace_id":       req.TraceID,
		"session_id":     req.SessionID,
		"server":         req.ServerName,
		"tool":           req.ToolName,
		"arguments":      req.Arguments,
		"escalation_jwt": escalationJWT,
		"user": map[string]any{
			"id":          req.UserIdentity.UserID,
			"display":     req.UserIdentity.DisplayName,
			"groups":      req.UserIdentity.Groups,
			"source_type": req.UserIdentity.SourceType,
		},
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
	return req.TraceID, nil
}
