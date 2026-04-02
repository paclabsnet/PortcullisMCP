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
	"context"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// makeLimitedServer creates a Guard server with limits fully populated via NewServer.
func makeLimitedServer(t *testing.T) *Server {
	t.Helper()
	s, err := newServerWithLimits(t, AuthConfig{AllowUnauthenticated: true})
	if err != nil {
		t.Fatalf("newServerWithLimits: %v", err)
	}
	return s
}

// newServerWithLimits creates a server with explicit limits. Limits default to
// values that match NewServer defaults when AllowUnauthenticated is set.
// The ready flags are pre-set so handleReadyz returns 200 in unit tests.
func newServerWithLimits(t *testing.T, auth AuthConfig) (*Server, error) {
	t.Helper()
	dir := t.TempDir()
	writeTempTemplates(t, dir)
	s, err := NewServer(context.Background(), Config{
		Listen:                 ListenConfig{UIAddress: ":0", APIAddress: ":0"},
		Keep:                   KeepConfig{PendingEscalationRequestSigningKey: testKeepKey},
		EscalationTokenSigning: SigningConfig{Key: testSigningKey, TTL: 3600},
		Templates:              TemplatesConfig{Dir: dir},
		Auth:                   auth,
	})
	if err == nil && s != nil {
		s.uiReady.Store(true)
		s.apiReady.Store(true)
	}
	return s, err
}

// makeServerDirect creates a Server struct directly without using NewServer,
// allowing tests to set limits explicitly without going through Validate().
// Use this only when testing middleware behaviour in isolation.
func makeServerDirect(auth AuthConfig, limits LimitsConfig) *Server {
	tmpl, _ := template.New("approval.html").Parse(`<html>{{.UserID}}</html>`)
	template.Must(tmpl.New("token.html").Parse(`<html>{{.EscalationToken}}</html>`))
	return &Server{
		cfg: Config{
			Auth:   auth,
			Limits: limits,
		},
		keepKey:    []byte(testKeepKey),
		signingKey: []byte(testSigningKey),
		ttl:        24 * time.Hour,
		templates:  tmpl,
		pending:    NewMemPendingStore(limits.MaxPendingRequests),
		unclaimed:  NewMemUnclaimedStore(limits.MaxUnclaimedPerUser, limits.MaxUnclaimedTotal),
	}
}

// ---- auth middleware tests --------------------------------------------------

func TestGuard_Auth_NoTokenNoFlag_Returns401(t *testing.T) {
	// Build a server directly with no bearer token and the flag explicitly false.
	s := makeServerDirect(AuthConfig{BearerToken: "", AllowUnauthenticated: false}, LimitsConfig{
		MaxRequestBodyBytes: 512 << 10,
		MaxUserIDBytes:      512,
		MaxJTIBytes:         128,
		MaxPendingJWTBytes:  8192,
	})

	body, _ := json.Marshal(map[string]string{"pending_jwt": "x", "user_id": "u"})
	req := httptest.NewRequest(http.MethodPost, "/token/deposit", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.machineAuth(s.handleTokenDeposit)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when no bearer token and flag is false", w.Code)
	}
}

func TestGuard_Auth_NoTokenWithFlag_Allowed(t *testing.T) {
	// Server with AllowUnauthenticated: true — /token/deposit should be reachable.
	s, err := newServerWithLimits(t, AuthConfig{AllowUnauthenticated: true})
	if err != nil {
		t.Fatalf("newServerWithLimits: %v", err)
	}

	// A valid pending JWT signed with testKeepKey.
	jwtStr := signKeepJWTWithID(t, "auth-test-jti", escalationRequestClaims{
		UserID: "user@example.com",
		Server: "srv",
		Tool:   "tool",
	}, time.Now().Add(time.Hour))

	body, _ := json.Marshal(map[string]string{
		"pending_jwt": jwtStr,
		"user_id":     "user@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/token/deposit", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.machineAuth(s.handleTokenDeposit)(w, req)

	// Should not be 401 — the flag allows unauthenticated access.
	if w.Code == http.StatusUnauthorized {
		t.Errorf("status = 401, want non-401 when AllowUnauthenticated is true")
	}
}

func TestGuard_Auth_WrongToken_Returns401(t *testing.T) {
	s := makeServerDirect(AuthConfig{BearerToken: "correct-secret"}, LimitsConfig{
		MaxRequestBodyBytes: 512 << 10,
		MaxUserIDBytes:      512,
		MaxPendingJWTBytes:  8192,
	})

	body, _ := json.Marshal(map[string]string{"pending_jwt": "x", "user_id": "u"})
	req := httptest.NewRequest(http.MethodPost, "/token/deposit", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	s.machineAuth(s.handleTokenDeposit)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for wrong bearer token", w.Code)
	}
}

// ---- field length validation tests -----------------------------------------

func TestGuard_Validation_JTITooLong_Returns400(t *testing.T) {
	s := makeLimitedServer(t)

	body, _ := json.Marshal(map[string]string{
		"jti": strings.Repeat("j", 129), // exceeds 128
	})
	req := httptest.NewRequest(http.MethodPost, "/token/claim", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleTokenClaim(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for oversized jti", w.Code)
	}
}

func TestGuard_Validation_PendingJWTTooLong_Returns400(t *testing.T) {
	s := makeLimitedServer(t)

	body, _ := json.Marshal(map[string]string{
		"pending_jwt": strings.Repeat("p", 8193), // exceeds 8192
		"user_id":     "user@example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/token/deposit", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleTokenDeposit(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for oversized pending_jwt", w.Code)
	}
}

// ---- expires_at in unclaimed list ------------------------------------------

func TestGuard_UnclaimedList_IncludesExpiresAt(t *testing.T) {
	s := makeLimitedServer(t)

	// Deposit a real token through the full handleTokenDeposit path.
	jwtStr := signKeepJWTWithID(t, "exp-test-jti", escalationRequestClaims{
		UserID: "list-user@example.com",
		Server: "srv",
		Tool:   "tool",
	}, time.Now().Add(time.Hour))

	depositBody, _ := json.Marshal(map[string]string{
		"pending_jwt": jwtStr,
		"user_id":     "list-user@example.com",
	})
	depReq := httptest.NewRequest(http.MethodPost, "/token/deposit", bytes.NewReader(depositBody))
	depW := httptest.NewRecorder()
	s.handleTokenDeposit(depW, depReq)
	if depW.Code != http.StatusCreated {
		t.Fatalf("deposit status = %d, want 201; body: %s", depW.Code, depW.Body.String())
	}

	// Now call the list endpoint.
	listReq := httptest.NewRequest(http.MethodGet, "/token/unclaimed/list?user_id=list-user@example.com", nil)
	listW := httptest.NewRecorder()
	s.handleTokenUnclaimedList(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", listW.Code)
	}

	var result []struct {
		JTI       string    `json:"jti"`
		Raw       string    `json:"raw"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(listW.Body).Decode(&result); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 unclaimed token, got %d", len(result))
	}
	if result[0].ExpiresAt.IsZero() {
		t.Error("expires_at should be non-zero in unclaimed list response")
	}
	if result[0].ExpiresAt.Before(time.Now()) {
		t.Error("expires_at should be in the future")
	}
}

// ---- remote_addr logging on token claim ------------------------------------

// slogCapture is a simple slog handler that captures all log records.
type slogCapture struct {
	mu      sync.Mutex
	records []slog.Record
}

func (c *slogCapture) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (c *slogCapture) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	c.records = append(c.records, r.Clone())
	c.mu.Unlock()
	return nil
}

func (c *slogCapture) WithAttrs(_ []slog.Attr) slog.Handler { return c }
func (c *slogCapture) WithGroup(_ string) slog.Handler       { return c }

// hasAttr returns true if any captured log record contains an attribute with the
// given key whose string value contains the given substring.
func (c *slogCapture) hasAttr(key, value string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rec := range c.records {
		found := false
		rec.Attrs(func(a slog.Attr) bool {
			if a.Key == key && strings.Contains(a.Value.String(), value) {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

func TestGuard_TokenClaim_LogsRemoteAddr(t *testing.T) {
	s := makeLimitedServer(t)

	// Seed an unclaimed token directly.
	if err := s.unclaimed.AddUnclaimed(context.Background(), UnclaimedToken{
		UserID:    "claim-addr-user",
		JTI:       "claim-addr-jti",
		Raw:       "raw-token",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("AddUnclaimed: %v", err)
	}

	// Capture slog output.
	capture := &slogCapture{}
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(capture))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	body, _ := json.Marshal(map[string]string{"jti": "claim-addr-jti"})
	req := httptest.NewRequest(http.MethodPost, "/token/claim", bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.1:9999"
	w := httptest.NewRecorder()
	s.handleTokenClaim(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Verify remote_addr was logged.
	if !capture.hasAttr("remote_addr", "10.0.0.1:9999") {
		t.Error("expected remote_addr to be logged on token claim")
	}
}
