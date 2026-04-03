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
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// makeLimitedServer creates a Guard server with limits fully populated via NewServer.
func makeLimitedServer(t *testing.T) *Server {
	t.Helper()
	cfg := validBaseConfig()
	// All limits default to 0 in base config, NewServer fills them.
	s, err := NewServer(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}

// ---- machineAuthMiddleware tests -------------------------------------------

func TestGuard_Auth_NoToken_Returns401(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Server.Endpoints["token_api"] = cfgloader.EndpointConfig{
		Listen: ":0",
		Auth: cfgloader.AuthSettings{
			Type: "bearer",
			Credentials: cfgloader.AuthCredentials{
				BearerToken: "correct-secret",
			},
		},
	}
	s, _ := NewServer(context.Background(), cfg)

	body, _ := json.Marshal(map[string]string{"jti": "j"})
	req := httptest.NewRequest(http.MethodPost, "/token/claim", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	s.machineAuthMiddleware(s.handleTokenClaim).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when no bearer token provided", w.Code)
	}
}

func TestGuard_Auth_WrongToken_Returns401(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Server.Endpoints["token_api"] = cfgloader.EndpointConfig{
		Listen: ":0",
		Auth: cfgloader.AuthSettings{
			Type: "bearer",
			Credentials: cfgloader.AuthCredentials{
				BearerToken: "correct-secret",
			},
		},
	}
	s, _ := NewServer(context.Background(), cfg)

	body, _ := json.Marshal(map[string]string{"jti": "j"})
	req := httptest.NewRequest(http.MethodPost, "/token/claim", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	s.machineAuthMiddleware(s.handleTokenClaim).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for wrong bearer token", w.Code)
	}
}

// ---- field length validation tests -----------------------------------------

func TestGuard_Validation_JTITooLong_Returns400(t *testing.T) {
	s := makeLimitedServer(t)

	body, _ := json.Marshal(map[string]string{
		"jti": strings.Repeat("j", 129), // exceeds default 128
	})
	req := httptest.NewRequest(http.MethodPost, "/token/claim", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	s.handleTokenClaim(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for oversized jti", w.Code)
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
			if a.Key == key && strings.Contains(fmt.Sprintf("%v", a.Value.Any()), value) {
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
	if err := s.unclaimedStore.AddUnclaimed(context.Background(), UnclaimedToken{
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
	req := httptest.NewRequest(http.MethodPost, "/token/claim", strings.NewReader(string(body)))
	req.RemoteAddr = "10.0.0.1:9999"
	w := httptest.NewRecorder()
	s.handleTokenClaim(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Verify remote_addr was logged.
	if !capture.hasAttr("remote_addr", "10.0.0.1:9999") {
		// Log what we DID find to help debug
		capture.mu.Lock()
		for _, r := range capture.records {
			t.Logf("Captured log: %s", r.Message)
			r.Attrs(func(a slog.Attr) bool {
				t.Logf("  attr: %s=%v", a.Key, a.Value)
				return true
			})
		}
		capture.mu.Unlock()
		t.Error("expected remote_addr to be logged on token claim")
	}
}
