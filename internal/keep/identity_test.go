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
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

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

// makeJWT builds a minimal unsigned JWT with the given claims for testing.
func makeJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + ".fakesig"
}

// --- strictNormalizer tests ---

func TestStrictNormalizer_OIDCPassesThrough(t *testing.T) {
	n := &strictNormalizer{}
	id := oidcIdentity()

	got, err := n.Normalize(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UserID != id.UserID || len(got.Groups) != len(id.Groups) {
		t.Errorf("OIDC identity should pass through unchanged; got %+v", got)
	}
}

func TestStrictNormalizer_OSStripsDirectoryClaims(t *testing.T) {
	n := &strictNormalizer{}
	id := osIdentity()

	got, err := n.Normalize(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UserID != id.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, id.UserID)
	}
	if got.SourceType != "os" {
		t.Errorf("SourceType = %q, want os", got.SourceType)
	}
	if len(got.Groups) != 0 {
		t.Errorf("Groups should be empty, got %v", got.Groups)
	}
	if len(got.Roles) != 0 {
		t.Errorf("Roles should be empty, got %v", got.Roles)
	}
	if got.Department != "" {
		t.Errorf("Department should be empty, got %q", got.Department)
	}
	if len(got.AuthMethod) != 0 {
		t.Errorf("AuthMethod should be empty, got %v", got.AuthMethod)
	}
	if got.DisplayName != "" {
		t.Errorf("DisplayName should be empty, got %q", got.DisplayName)
	}
}

// --- passthroughNormalizer tests ---

func TestPassthroughNormalizer_AcceptsAll(t *testing.T) {
	n := &passthroughNormalizer{silenced: true}

	for _, id := range []shared.UserIdentity{oidcIdentity(), osIdentity()} {
		got, err := n.Normalize(context.Background(), id)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", id.SourceType, err)
		}
		if got.UserID != id.UserID || len(got.Groups) != len(id.Groups) {
			t.Errorf("passthrough should not modify identity; got %+v", got)
		}
	}
}

// --- oidcVerifyingNormalizer tests ---

func TestOIDCVerifyingNormalizer_ValidToken(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	raw := makeJWT(map[string]any{"iss": "https://idp.example.com", "sub": "alice", "exp": exp})

	n := &oidcVerifyingNormalizer{issuer: "https://idp.example.com", strict: &strictNormalizer{}}
	id := oidcIdentity()
	id.RawToken = raw
	id.TokenExpiry = exp

	got, err := n.Normalize(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UserID != id.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, id.UserID)
	}
}

func TestOIDCVerifyingNormalizer_ExpiredToken(t *testing.T) {
	n := &oidcVerifyingNormalizer{issuer: "https://idp.example.com", strict: &strictNormalizer{}}
	id := oidcIdentity()
	id.TokenExpiry = time.Now().Add(-time.Minute).Unix() // expired

	_, err := n.Normalize(context.Background(), id)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestOIDCVerifyingNormalizer_WrongIssuer(t *testing.T) {
	raw := makeJWT(map[string]any{"iss": "https://attacker.example.com", "sub": "alice"})

	n := &oidcVerifyingNormalizer{issuer: "https://idp.example.com", strict: &strictNormalizer{}}
	id := oidcIdentity()
	id.RawToken = raw

	_, err := n.Normalize(context.Background(), id)
	if err == nil {
		t.Fatal("expected error for wrong issuer, got nil")
	}
}

func TestOIDCVerifyingNormalizer_OSAppliesStrict(t *testing.T) {
	n := &oidcVerifyingNormalizer{issuer: "https://idp.example.com", strict: &strictNormalizer{}}
	id := osIdentity()

	got, err := n.Normalize(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Groups) != 0 {
		t.Errorf("OS identity groups should be stripped by oidc-verify normalizer, got %v", got.Groups)
	}
}

// --- buildIdentityNormalizer factory tests ---

func TestBuildIdentityNormalizer_DefaultIsStrict(t *testing.T) {
	n, err := buildIdentityNormalizer(IdentityConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := n.(*strictNormalizer); !ok {
		t.Errorf("expected *strictNormalizer, got %T", n)
	}
}

func TestBuildIdentityNormalizer_Passthrough(t *testing.T) {
	n, err := buildIdentityNormalizer(IdentityConfig{Normalizer: "passthrough"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := n.(*passthroughNormalizer); !ok {
		t.Errorf("expected *passthroughNormalizer, got %T", n)
	}
}

func TestBuildIdentityNormalizer_OIDCVerify(t *testing.T) {
	n, err := buildIdentityNormalizer(IdentityConfig{
		Normalizer: "oidc-verify",
		OIDCVerify: OIDCVerifyConfig{Issuer: "https://idp.example.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := n.(*oidcVerifyingNormalizer); !ok {
		t.Errorf("expected *oidcVerifyingNormalizer, got %T", n)
	}
}

func TestBuildIdentityNormalizer_OIDCVerifyMissingIssuer(t *testing.T) {
	_, err := buildIdentityNormalizer(IdentityConfig{Normalizer: "oidc-verify"})
	if err == nil {
		t.Fatal("expected error when issuer is missing, got nil")
	}
}

func TestBuildIdentityNormalizer_UnknownNormalizer(t *testing.T) {
	_, err := buildIdentityNormalizer(IdentityConfig{Normalizer: "bogus"})
	if err == nil {
		t.Fatal("expected error for unknown normalizer, got nil")
	}
}

// TestNormalizeIdentity_HandleCallIntegration verifies that identity
// normalization is applied by handleCall before the PDP sees the request.
func TestNormalizeIdentity_HandleCallIntegration(t *testing.T) {
	pdp := &capturingPDP{}
	srv := &Server{
		normalizer:  &strictNormalizer{},
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
		TraceID: "req-1",
	}
	body, _ := json.Marshal(req)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/call", bytes.NewReader(body))
	srv.handleCall(w, r)

	captured := pdp.lastPrincipal
	if len(captured.Groups) != 0 {
		t.Errorf("PDP received groups %v — strict normalizer should have stripped them", captured.Groups)
	}
	if captured.UserID != "alice" {
		t.Errorf("PDP received UserID %q, want alice", captured.UserID)
	}
}

// capturingPDP records the last request it evaluated, for inspection in tests.
type capturingPDP struct {
	lastReq       shared.EnrichedMCPRequest
	lastPrincipal shared.Principal
}

func (c *capturingPDP) Evaluate(_ context.Context, req shared.EnrichedMCPRequest, p shared.Principal) (shared.PDPResponse, error) {
	c.lastReq = req
	c.lastPrincipal = p
	return shared.PDPResponse{Decision: "allow"}, nil
}

func TestRegisterNormalizer(t *testing.T) {
	name := "custom-test"
	RegisterNormalizer(name, func(cfg IdentityConfig) (IdentityNormalizer, error) {
		return &strictNormalizer{}, nil
	})

	n, err := buildIdentityNormalizer(IdentityConfig{Normalizer: name})
	if err != nil {
		t.Fatalf("failed to build custom normalizer: %v", err)
	}
	if _, ok := n.(*strictNormalizer); !ok {
		t.Errorf("expected *strictNormalizer, got %T", n)
	}
}
