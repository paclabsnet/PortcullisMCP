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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
)

func TestNewEscalationSigner_NoKey(t *testing.T) {
	signer, err := NewEscalationSigner(SigningConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer != nil {
		t.Error("expected nil signer when no key configured")
	}
}

func TestNewEscalationSigner_WithKey(t *testing.T) {
	signer, err := NewEscalationSigner(SigningConfig{Key: "secret-key", TTL: 3600})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestEscalationSigner_Sign(t *testing.T) {
	signer, _ := NewEscalationSigner(SigningConfig{Key: "test-signing-key", TTL: 3600})

	req := shared.EnrichedMCPRequest{
		ServerName: "github",
		ToolName:   "create_issue",
		TraceID:    "req-123",
	}
	p := shared.Principal{
		UserID:      "user@example.com",
		DisplayName: "Test User",
	}
	scope := []map[string]any{{"resource": "repo:example"}}

	tokenStr, jti, err := signer.Sign(NewAuthorizedRequest(req, p), "manager approval needed", scope)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token string")
	}
	if jti == "" {
		t.Fatal("expected non-empty JTI")
	}

	// Parse and verify the signed token.
	token, err := jwt.ParseWithClaims(tokenStr, &escalationRequestClaims{}, func(t *jwt.Token) (any, error) {
		return []byte("test-signing-key"), nil
	})
	if err != nil {
		t.Fatalf("failed to parse signed token: %v", err)
	}

	claims, ok := token.Claims.(*escalationRequestClaims)
	if !ok || !token.Valid {
		t.Fatal("expected valid token claims")
	}
	if claims.ID != jti {
		t.Errorf("JTI in claims = %q, want returned jti %q", claims.ID, jti)
	}
	if claims.UserID != "user@example.com" {
		t.Errorf("UserID = %q, want user@example.com", claims.UserID)
	}
	if claims.UserDisplayName != "Test User" {
		t.Errorf("UserDisplayName = %q, want Test User", claims.UserDisplayName)
	}
	if claims.Server != "github" {
		t.Errorf("Server = %q, want github", claims.Server)
	}
	if claims.Tool != "create_issue" {
		t.Errorf("Tool = %q, want create_issue", claims.Tool)
	}
	if claims.Reason != "manager approval needed" {
		t.Errorf("Reason = %q, want 'manager approval needed'", claims.Reason)
	}
	if claims.Issuer != shared.IssuerKeep {
		t.Errorf("Issuer = %q, want portcullis-keep", claims.Issuer)
	}
	if claims.ExpiresAt == nil || claims.ExpiresAt.Before(time.Now()) {
		t.Error("expected future expiry in signed token")
	}
	if len(claims.EscalationScope) == 0 || claims.EscalationScope[0]["resource"] != "repo:example" {
		t.Errorf("EscalationScope[0].resource = %v, want repo:example", claims.EscalationScope)
	}
}

func TestEscalationSigner_Sign_DefaultTTL(t *testing.T) {
	// TTL=0 should default to 24 hours.
	signer, _ := NewEscalationSigner(SigningConfig{Key: "k", TTL: 0})
	req := shared.EnrichedMCPRequest{
		ServerName: "s",
		ToolName:   "t",
	}
	p := shared.Principal{UserID: "u@example.com"}

	tokenStr, _, err := signer.Sign(NewAuthorizedRequest(req, p), "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	token, err := jwt.ParseWithClaims(tokenStr, &escalationRequestClaims{}, func(t *jwt.Token) (any, error) {
		return []byte("k"), nil
	})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	claims := token.Claims.(*escalationRequestClaims)

	expected := time.Now().Add(24 * time.Hour)
	diff := claims.ExpiresAt.Time.Sub(expected)
	if diff < 0 {
		diff = -diff
	}
	if diff > 5*time.Second {
		t.Errorf("default TTL should be 24 hours; expiry differs from expected by %v", diff)
	}
}

func TestEscalationSigner_Sign_CustomTTL(t *testing.T) {
	signer, _ := NewEscalationSigner(SigningConfig{Key: "k", TTL: 7200}) // 2 hours
	req := shared.EnrichedMCPRequest{
		ServerName: "s",
		ToolName:   "t",
	}
	p := shared.Principal{UserID: "u@example.com"}

	tokenStr, _, _ := signer.Sign(NewAuthorizedRequest(req, p), "", nil)
	token, _ := jwt.ParseWithClaims(tokenStr, &escalationRequestClaims{}, func(t *jwt.Token) (any, error) {
		return []byte("k"), nil
	})
	claims := token.Claims.(*escalationRequestClaims)

	expected := time.Now().Add(2 * time.Hour)
	diff := claims.ExpiresAt.Time.Sub(expected)
	if diff < 0 {
		diff = -diff
	}
	if diff > 5*time.Second {
		t.Errorf("TTL=7200 should give 2 hour expiry; diff = %v", diff)
	}
}

func TestEscalationSigner_Sign_NilSigner(t *testing.T) {
	var s *EscalationSigner
	_, _, err := s.Sign(AuthorizedRequest{}, "", nil)
	if err == nil {
		t.Error("expected error from nil signer, got nil")
	}
}

func TestEscalationSigner_Sign_NilScope(t *testing.T) {
	// nil scope should produce a valid token with no scope field.
	signer, _ := NewEscalationSigner(SigningConfig{Key: "k", TTL: 60})
	req := shared.EnrichedMCPRequest{
		ServerName: "s",
		ToolName:   "t",
	}
	p := shared.Principal{UserID: "u@example.com"}
	_, _, err := signer.Sign(NewAuthorizedRequest(req, p), "reason", nil)
	if err != nil {
		t.Fatalf("Sign with nil scope returned error: %v", err)
	}
}
