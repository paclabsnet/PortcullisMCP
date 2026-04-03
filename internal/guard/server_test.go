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

package guard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

const (
	testKeepKey    = "test-keep-signing-key-32bytes!!"
	testSigningKey = "test-escalation-signing-key-32b!"
)

func makeServer(t *testing.T) *Server {
	t.Helper()
	cfg := Config{
		Server: cfgloader.ServerConfig{
			Endpoints: map[string]cfgloader.EndpointConfig{
				"approval_ui": {Listen: ":0"},
				"token_api":   {Listen: ":0"},
			},
		},
		Responsibility: ResponsibilityConfig{
			Issuance: IssuanceConfig{
				ApprovalRequestVerificationKey: testKeepKey,
				SigningKey:                     testSigningKey,
				TokenTTL:                       3600,
			},
		},
	}
	s, err := NewServer(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.uiReady.Store(true)
	s.apiReady.Store(true)
	return s
}

// signKeepJWT signs an escalation request JWT exactly as Keep would.
func signKeepJWT(t *testing.T, claims escalationRequestClaims, expiry time.Time) string {
	t.Helper()
	if claims.RegisteredClaims.Issuer == "" {
		claims.RegisteredClaims.Issuer = shared.ServiceKeep
	}
	claims.RegisteredClaims.IssuedAt = jwt.NewNumericDate(time.Now())
	claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(expiry)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(testKeepKey))
	if err != nil {
		t.Fatalf("sign test JWT: %v", err)
	}
	return signed
}

func signKeepJWTWithID(t *testing.T, id string, claims escalationRequestClaims, expiry time.Time) string {
	t.Helper()
	claims.RegisteredClaims.ID = id
	return signKeepJWT(t, claims, expiry)
}

func TestNewServer_MissingKeys(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Responsibility.Issuance.ApprovalRequestVerificationKey = ""
	_, err := NewServer(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for missing verification key")
	}

	cfg = validBaseConfig()
	cfg.Responsibility.Issuance.SigningKey = ""
	_, err = NewServer(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for missing signing key")
	}
}

func TestVerifyRequest_Valid(t *testing.T) {
	s := makeServer(t)
	tokenStr := signKeepJWT(t, escalationRequestClaims{
		UserID: "alice@corp.com",
		Server: "github",
		Tool:   "push",
		Reason: "deploy",
	}, time.Now().Add(time.Hour))

	claims, err := s.verifyRequest(tokenStr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.UserID != "alice@corp.com" {
		t.Errorf("UserID = %q, want alice@corp.com", claims.UserID)
	}
}

func TestIssueEscalationToken_Claims(t *testing.T) {
	s := makeServer(t)

	scope := []map[string]any{{"repo": "example/repo"}}
	requestClaims := &escalationRequestClaims{
		UserID:          "alice@corp.com",
		UserDisplayName: "Alice",
		Server:          "github",
		Tool:            "create_issue",
		EscalationScope: scope,
	}

	tokenStr, _, err := s.issueEscalationToken(requestClaims, "test-jti-123", scope)
	if err != nil {
		t.Fatalf("issueEscalationToken: %v", err)
	}

	parsed, err := jwt.ParseWithClaims(tokenStr, &escalationTokenClaims{}, func(t *jwt.Token) (any, error) {
		return []byte(testSigningKey), nil
	})
	if err != nil {
		t.Fatalf("parse issued token: %v", err)
	}
	tc := parsed.Claims.(*escalationTokenClaims)
	if tc.Subject != "alice@corp.com" {
		t.Errorf("Subject = %q, want alice@corp.com", tc.Subject)
	}
	if tc.ID != "test-jti-123" {
		t.Errorf("JTI = %q, want test-jti-123", tc.ID)
	}
}

func TestHandleApprovePage_MissingToken(t *testing.T) {
	s := makeServer(t)
	req := httptest.NewRequest(http.MethodGet, "/approve", nil)
	w := httptest.NewRecorder()
	s.handleApprovePage(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleApproveAction_ValidApproval(t *testing.T) {
	s := makeServer(t)

	tokenStr := signKeepJWT(t, escalationRequestClaims{
		UserID: "alice@corp.com",
		Server: "github",
		Tool:   "push",
	}, time.Now().Add(time.Hour))

	form := url.Values{"token": {tokenStr}}
	req := httptest.NewRequest(http.MethodPost, "/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleApproveAction(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandlePendingStore_Valid(t *testing.T) {
	s := makeServer(t)
	jti := "test-pending-jti"
	jwtStr := signKeepJWTWithID(t, jti, escalationRequestClaims{
		UserID: "alice@corp.com",
	}, time.Now().Add(time.Hour))

	body, _ := json.Marshal(map[string]string{"jti": jti, "jwt": jwtStr})
	req := httptest.NewRequest(http.MethodPost, "/pending", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handlePendingStore(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", w.Code)
	}
}
