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
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

// oidcIdentity returns a fully-populated OIDC-sourced identity for use in tests.
func oidcIdentity() shared.UserIdentity {
	return shared.UserIdentity{
		UserID:      "alice@corp.com",
		DisplayName: "Alice",
		Groups:      []string{"developers", "admins"},
		Roles:       []string{"deploy"},
		Department:  "Engineering",
		AuthMethod:  []string{"pwd", "mfa"},
		RawToken:    "eyJ...",
		SourceType:  "oidc",
	}
}

// osIdentity returns a fully-populated OS-sourced identity for use in tests.
func osIdentity() shared.UserIdentity {
	return shared.UserIdentity{
		UserID:      "alice",
		DisplayName: "Alice",
		Groups:      []string{"developers", "admins"},
		Roles:       []string{"deploy"},
		Department:  "Engineering",
		AuthMethod:  []string{"os"},
		RawToken:    "fake-token",
		SourceType:  "os",
	}
}

func TestNormalizeIdentity_OIDCPassesThrough(t *testing.T) {
	id := oidcIdentity()
	cfg := IdentityConfig{Mode: "strict"}

	got := normalizeIdentity(id, cfg)

	// OIDC identity must be returned unchanged in both modes.
	if got.UserID != id.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, id.UserID)
	}
	if len(got.Groups) != len(id.Groups) {
		t.Errorf("Groups = %v, want %v", got.Groups, id.Groups)
	}
	if got.RawToken != id.RawToken {
		t.Errorf("RawToken stripped for OIDC identity — should be preserved")
	}
	if got.Department != id.Department {
		t.Errorf("Department = %q, want %q", got.Department, id.Department)
	}
}

func TestNormalizeIdentity_OIDCPassesThroughInDemoMode(t *testing.T) {
	id := oidcIdentity()
	cfg := IdentityConfig{Mode: "demo", AcceptForgedIdentities: true}

	got := normalizeIdentity(id, cfg)

	if got.UserID != id.UserID || len(got.Groups) != len(id.Groups) {
		t.Errorf("OIDC identity should pass through in demo mode unchanged")
	}
}

func TestNormalizeIdentity_StrictMode_OSStripsDirectoryClaims(t *testing.T) {
	id := osIdentity()
	cfg := IdentityConfig{Mode: "strict"}

	got := normalizeIdentity(id, cfg)

	if got.UserID != id.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, id.UserID)
	}
	if got.SourceType != "os" {
		t.Errorf("SourceType = %q, want os", got.SourceType)
	}
	if len(got.Groups) != 0 {
		t.Errorf("Groups should be empty in strict mode, got %v", got.Groups)
	}
	if len(got.Roles) != 0 {
		t.Errorf("Roles should be empty in strict mode, got %v", got.Roles)
	}
	if got.Department != "" {
		t.Errorf("Department should be empty in strict mode, got %q", got.Department)
	}
	if len(got.AuthMethod) != 0 {
		t.Errorf("AuthMethod should be empty in strict mode, got %v", got.AuthMethod)
	}
	if got.RawToken != "" {
		t.Errorf("RawToken should be empty in strict mode, got %q", got.RawToken)
	}
	if got.DisplayName != "" {
		t.Errorf("DisplayName should be empty in strict mode, got %q", got.DisplayName)
	}
}

func TestNormalizeIdentity_DefaultModeIsStrict(t *testing.T) {
	// Mode: "" should behave identically to Mode: "strict".
	id := osIdentity()
	withEmpty := normalizeIdentity(id, IdentityConfig{Mode: ""})
	withStrict := normalizeIdentity(id, IdentityConfig{Mode: "strict"})

	if withEmpty.UserID != withStrict.UserID || len(withEmpty.Groups) != len(withStrict.Groups) {
		t.Errorf("empty mode should default to strict behaviour")
	}
	if len(withEmpty.Groups) != 0 {
		t.Errorf("directory claims should be stripped when mode is empty")
	}
}

func TestNormalizeIdentity_DemoMode_OSPassesThrough(t *testing.T) {
	id := osIdentity()
	cfg := IdentityConfig{Mode: "demo", AcceptForgedIdentities: true}

	got := normalizeIdentity(id, cfg)

	if got.UserID != id.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, id.UserID)
	}
	if len(got.Groups) != len(id.Groups) {
		t.Errorf("Groups = %v, want %v in demo mode", got.Groups, id.Groups)
	}
	if got.RawToken != id.RawToken {
		t.Errorf("RawToken stripped in demo mode — should be preserved")
	}
}

func TestNormalizeIdentity_UnknownModeDefaultsToStrict(t *testing.T) {
	id := osIdentity()
	cfg := IdentityConfig{Mode: "unknown-value"}

	got := normalizeIdentity(id, cfg)

	if len(got.Groups) != 0 {
		t.Errorf("unknown mode should default to strict, but groups were not stripped: %v", got.Groups)
	}
	if got.UserID != id.UserID {
		t.Errorf("UserID should be preserved even in unknown mode fallback")
	}
}

// TestNormalizeIdentity_HandleCallIntegration verifies that identity
// normalisation is applied by handleCall before the PDP sees the request.
func TestNormalizeIdentity_HandleCallIntegration(t *testing.T) {
	var capturedReq shared.EnrichedMCPRequest

	pdp := &capturingPDP{}
	srv := &Server{
		cfg: Config{
			Identity: IdentityConfig{Mode: "strict"},
		},
		pdp:         pdp,
		router:      &mockRouter{callToolResult: &mcp.CallToolResult{}},
		workflow:    &mockWorkflow{requestID: "wf-1"},
		decisionLog: NewDecisionLogger(DecisionLogConfig{}),
	}

	req := shared.EnrichedMCPRequest{
		ServerName: "test-server",
		ToolName:   "test-tool",
		UserIdentity: shared.UserIdentity{
			UserID:     "alice",
			Groups:     []string{"admins"},
			SourceType: "os",
		},
		RequestID: "req-1",
	}
	body, _ := json.Marshal(req)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/call", bytes.NewReader(body))
	srv.handleCall(w, r)

	capturedReq = pdp.lastReq
	if len(capturedReq.UserIdentity.Groups) != 0 {
		t.Errorf("PDP received groups %v — strict mode should have stripped them", capturedReq.UserIdentity.Groups)
	}
	if capturedReq.UserIdentity.UserID != "alice" {
		t.Errorf("PDP received UserID %q, want alice", capturedReq.UserIdentity.UserID)
	}
}

// capturingPDP records the last request it evaluated, for inspection in tests.
type capturingPDP struct {
	lastReq shared.EnrichedMCPRequest
}

func (c *capturingPDP) Evaluate(_ context.Context, req shared.EnrichedMCPRequest) (shared.PDPResponse, error) {
	c.lastReq = req
	return shared.PDPResponse{Decision: "allow"}, nil
}
