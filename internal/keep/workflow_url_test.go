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
	"testing"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

func TestNewURLWorkflowHandler_MissingGuardURL(t *testing.T) {
	_, err := newURLWorkflowHandler(URLWorkflowConfig{})
	if err == nil {
		t.Fatal("expected error for missing endpoints.approval_ui, got nil")
	}
}

func TestNewURLWorkflowHandler_Valid(t *testing.T) {
	h, err := newURLWorkflowHandler(URLWorkflowConfig{
		Endpoints: cfgloader.GuardEndpoints{ApprovalUI: "https://guard.example.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestURLWorkflowHandler_Submit_ReturnsEmpty(t *testing.T) {
	// Submit now always returns an empty reference regardless of JWT content.
	// Gate is responsible for building the approval URL from escalation_jti or
	// pending_jwt depending on its approval_management_strategy config.
	h, _ := newURLWorkflowHandler(URLWorkflowConfig{
		Endpoints: cfgloader.GuardEndpoints{ApprovalUI: "https://guard.example.com"},
	})

	for _, jwt := range []string{"", "my.jwt.token", "token.payload.sig"} {
		ref, err := h.Submit(context.Background(), NewAuthorizedRequest(shared.EnrichedMCPRequest{TraceID: "r"}, shared.Principal{}), jwt)
		if err != nil {
			t.Fatalf("Submit(%q): unexpected error: %v", jwt, err)
		}
		if ref != "" {
			t.Errorf("Submit(%q): reference = %q, want empty string", jwt, ref)
		}
	}
}

func TestNewWorkflowHandler_URLType(t *testing.T) {
	cfg := EscalationConfig{
		Strategy: "url",
		URL: URLWorkflowConfig{
			Endpoints: cfgloader.GuardEndpoints{ApprovalUI: "https://guard.example.com"},
		},
	}
	h, err := NewWorkflowHandler(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil handler for url type")
	}
}

func TestNewWorkflowHandler_URLType_MissingGuardURL(t *testing.T) {
	cfg := EscalationConfig{
		Strategy: "url",
		URL:      URLWorkflowConfig{}, // missing endpoints.approval_ui
	}
	_, err := NewWorkflowHandler(cfg)
	if err == nil {
		t.Fatal("expected error for url type with missing endpoints.approval_ui, got nil")
	}
}
