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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---- handleTokenUnclaimedList -----------------------------------------------

func TestHandleTokenUnclaimedList_MissingUserID(t *testing.T) {
	s := makeServer(t)
	req := httptest.NewRequest(http.MethodGet, "/token/unclaimed/list", nil)
	w := httptest.NewRecorder()
	s.handleTokenUnclaimedList(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleTokenUnclaimedList_EmptyForUnknownUser(t *testing.T) {
	s := makeServer(t)
	req := httptest.NewRequest(http.MethodGet, "/token/unclaimed/list?user_id=nobody@example.com", nil)
	w := httptest.NewRecorder()
	s.handleTokenUnclaimedList(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var result []map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty list for unknown user, got %d entries", len(result))
	}
}

func TestHandleTokenUnclaimedList_ReturnsTokensForUser(t *testing.T) {
	s := makeServer(t)
	// Directly seed an unclaimed token.
	s.addUnclaimed("user@example.com", "jti-abc", "raw-token-value", time.Now().Add(time.Hour))

	req := httptest.NewRequest(http.MethodGet, "/token/unclaimed/list?user_id=user@example.com", nil)
	w := httptest.NewRecorder()
	s.handleTokenUnclaimedList(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var result []map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 token, got %d", len(result))
	}
	if result[0]["jti"] != "jti-abc" {
		t.Errorf("jti = %q, want %q", result[0]["jti"], "jti-abc")
	}
}

// ---- handleTokenDeposit -----------------------------------------------------

func TestHandleTokenDeposit_InvalidJSON(t *testing.T) {
	s := makeServer(t)
	req := httptest.NewRequest(http.MethodPost, "/token/deposit", strings.NewReader("not-json"))
	w := httptest.NewRecorder()
	s.handleTokenDeposit(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleTokenDeposit_MissingFields(t *testing.T) {
	s := makeServer(t)
	body, _ := json.Marshal(map[string]string{"pending_jwt": "tok"}) // missing user_id
	req := httptest.NewRequest(http.MethodPost, "/token/deposit", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleTokenDeposit(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleTokenDeposit_InvalidJWT(t *testing.T) {
	s := makeServer(t)
	body, _ := json.Marshal(map[string]string{
		"pending_jwt": "not.a.valid.jwt",
		"user_id":     "user@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/token/deposit", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleTokenDeposit(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestHandleTokenDeposit_ValidJWT_CreatesUnclaimedToken(t *testing.T) {
	s := makeServer(t)
	pendingJWT := signKeepJWTWithID(t, "deposit-jti-123", escalationRequestClaims{
		UserID: "user@example.com",
		Server: "test-server",
		Tool:   "test-tool",
	}, time.Now().Add(time.Hour))

	body, _ := json.Marshal(map[string]string{
		"pending_jwt": pendingJWT,
		"user_id":     "user@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/token/deposit", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleTokenDeposit(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["status"] != "deposited" {
		t.Errorf("status = %q, want %q", result["status"], "deposited")
	}
	if result["jti"] != "deposit-jti-123" {
		t.Errorf("jti = %q, want %q", result["jti"], "deposit-jti-123")
	}

	// Verify the token appeared in the unclaimed list.
	listReq := httptest.NewRequest(http.MethodGet, "/token/unclaimed/list?user_id=user@example.com", nil)
	listW := httptest.NewRecorder()
	s.handleTokenUnclaimedList(listW, listReq)
	var tokens []map[string]string
	_ = json.NewDecoder(listW.Body).Decode(&tokens)
	if len(tokens) != 1 {
		t.Errorf("expected 1 unclaimed token after deposit, got %d", len(tokens))
	}
}

func TestHandleTokenDeposit_UserIDMismatch(t *testing.T) {
	s := makeServer(t)
	pendingJWT := signKeepJWT(t, escalationRequestClaims{
		UserID: "alice@example.com",
		Server: "test-server",
		Tool:   "test-tool",
	}, time.Now().Add(time.Hour))

	body, _ := json.Marshal(map[string]string{
		"pending_jwt": pendingJWT,
		"user_id":     "bob@example.com", // mismatch
	})
	req := httptest.NewRequest(http.MethodPost, "/token/deposit", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleTokenDeposit(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for user_id mismatch", w.Code)
	}
}

// ---- handleTokenClaim -------------------------------------------------------

func TestHandleTokenClaim_InvalidJSON(t *testing.T) {
	s := makeServer(t)
	req := httptest.NewRequest(http.MethodPost, "/token/claim", strings.NewReader("not-json"))
	w := httptest.NewRecorder()
	s.handleTokenClaim(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleTokenClaim_MissingJTI(t *testing.T) {
	s := makeServer(t)
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/token/claim", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleTokenClaim(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleTokenClaim_NotFound(t *testing.T) {
	s := makeServer(t)
	body, _ := json.Marshal(map[string]string{"jti": "nonexistent-jti"})
	req := httptest.NewRequest(http.MethodPost, "/token/claim", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleTokenClaim(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleTokenClaim_Success_AndConsumed(t *testing.T) {
	s := makeServer(t)
	s.addUnclaimed("user@example.com", "claim-jti", "the-escalation-token", time.Now().Add(time.Hour))

	body, _ := json.Marshal(map[string]string{"jti": "claim-jti"})

	// First claim — should succeed.
	req := httptest.NewRequest(http.MethodPost, "/token/claim", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleTokenClaim(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first claim status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["raw"] != "the-escalation-token" {
		t.Errorf("raw = %q, want %q", result["raw"], "the-escalation-token")
	}

	// Second claim on the same JTI — must return 404 (consumed).
	body2, _ := json.Marshal(map[string]string{"jti": "claim-jti"})
	req2 := httptest.NewRequest(http.MethodPost, "/token/claim", bytes.NewReader(body2))
	w2 := httptest.NewRecorder()
	s.handleTokenClaim(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Errorf("second claim status = %d, want 404 (token already consumed)", w2.Code)
	}
}
