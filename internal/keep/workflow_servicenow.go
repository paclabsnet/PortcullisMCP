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
// The escalationJWT is included in the description so the approver can embed
// it in a Guard approval URL or send it directly to the requesting user.
func (h *serviceNowHandler) Submit(ctx context.Context, req shared.EnrichedMCPRequest, escalationJWT string) (string, error) {
	body := map[string]any{
		"short_description": fmt.Sprintf(
			"Portcullis escalation: %s/%s requested by %s",
			req.ServerName, req.ToolName, req.UserIdentity.UserID,
		),
		"description": fmt.Sprintf(
			"Tool: %s\nServer: %s\nUser: %s (%s)\nRequest ID: %s\nSession ID: %s\nEscalation JWT: %s",
			req.ToolName, req.ServerName,
			req.UserIdentity.DisplayName, req.UserIdentity.UserID,
			req.RequestID, req.SessionID, escalationJWT,
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
