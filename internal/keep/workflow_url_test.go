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
	"strings"
	"testing"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

func TestNewURLWorkflowHandler_MissingGuardURL(t *testing.T) {
	_, err := newURLWorkflowHandler(URLWorkflowConfig{})
	if err == nil {
		t.Fatal("expected error for missing guard_url, got nil")
	}
}

func TestNewURLWorkflowHandler_Valid(t *testing.T) {
	h, err := newURLWorkflowHandler(URLWorkflowConfig{GuardURL: "https://guard.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestURLWorkflowHandler_Submit_MissingJWT(t *testing.T) {
	h, _ := newURLWorkflowHandler(URLWorkflowConfig{GuardURL: "https://guard.example.com"})
	_, err := h.Submit(context.Background(), shared.EnrichedMCPRequest{TraceID: "r"}, "")
	if err == nil {
		t.Fatal("expected error for missing escalation JWT, got nil")
	}
}

func TestURLWorkflowHandler_Submit_URLConstruction(t *testing.T) {
	h, _ := newURLWorkflowHandler(URLWorkflowConfig{GuardURL: "https://guard.example.com"})

	ref, err := h.Submit(context.Background(), shared.EnrichedMCPRequest{TraceID: "r"}, "my.jwt.token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "https://guard.example.com/approve?token=my.jwt.token"
	if ref != want {
		t.Errorf("reference = %q, want %q", ref, want)
	}
}

func TestURLWorkflowHandler_Submit_ContainsGuardURL(t *testing.T) {
	h, _ := newURLWorkflowHandler(URLWorkflowConfig{GuardURL: "https://guard.internal.corp"})

	ref, err := h.Submit(context.Background(), shared.EnrichedMCPRequest{}, "some.jwt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(ref, "https://guard.internal.corp") {
		t.Errorf("reference %q should start with guard URL", ref)
	}
	if !strings.Contains(ref, "some.jwt") {
		t.Errorf("reference %q should contain the JWT", ref)
	}
}

func TestURLWorkflowHandler_Submit_RequestIgnored(t *testing.T) {
	// The URL workflow ignores the EnrichedMCPRequest — only the JWT matters.
	h, _ := newURLWorkflowHandler(URLWorkflowConfig{GuardURL: "https://guard.example.com"})

	req := shared.EnrichedMCPRequest{
		ServerName: "github",
		ToolName:   "push_code",
		TraceID:  "req-xyz",
	}
	ref, err := h.Submit(context.Background(), req, "token.payload.sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Reference should only depend on guardURL + JWT, not on request fields.
	want := "https://guard.example.com/approve?token=token.payload.sig"
	if ref != want {
		t.Errorf("reference = %q, want %q", ref, want)
	}
}

func TestNewWorkflowHandler_URLType(t *testing.T) {
	cfg := WorkflowConfig{
		Type: "url",
		URL:  URLWorkflowConfig{GuardURL: "https://guard.example.com"},
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
	cfg := WorkflowConfig{
		Type: "url",
		URL:  URLWorkflowConfig{}, // missing guard_url
	}
	_, err := NewWorkflowHandler(cfg)
	if err == nil {
		t.Fatal("expected error for url type with missing guard_url, got nil")
	}
}
