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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// newTestClient builds a NormalizationClient pointed at srv with a 128 KB payload limit.
func newTestClient(t *testing.T, srv *httptest.Server, token string) *NormalizationClient {
	t.Helper()
	cfg := cfgloader.NormalizationPeerConfig{
		MaxPayloadKB: 128,
		Timeout:      5,
	}
	cfg.Endpoint = srv.URL
	if token != "" {
		cfg.Auth.Type = "bearer"
		cfg.Auth.Credentials.BearerToken = token
	}
	client, err := newNormalizationClient(cfg, cfgloader.ModeDev)
	if err != nil {
		t.Fatalf("newNormalizationClient: %v", err)
	}
	return client
}

func TestNormalizationClient_Success(t *testing.T) {
	want := shared.Principal{UserID: "alice", Email: "alice@corp.com", Groups: []string{"admins"}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	client := newTestClient(t, srv, "")
	got, err := client.Normalize(context.Background(), map[string]any{"sub": "alice"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UserID != want.UserID {
		t.Errorf("UserID = %q, want %q", got.UserID, want.UserID)
	}
	if got.Email != want.Email {
		t.Errorf("Email = %q, want %q", got.Email, want.Email)
	}
}

func TestNormalizationClient_SendsBearerToken(t *testing.T) {
	const secret = "super-secret-token"
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(shared.Principal{UserID: "alice"})
	}))
	defer srv.Close()

	client := newTestClient(t, srv, secret)
	_, err := client.Normalize(context.Background(), map[string]any{"sub": "alice"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer "+secret {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer "+secret)
	}
}

func TestNormalizationClient_NoTokenSendsNoAuthHeader(t *testing.T) {
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(shared.Principal{UserID: "alice"})
	}))
	defer srv.Close()

	client := newTestClient(t, srv, "")
	_, err := client.Normalize(context.Background(), map[string]any{"sub": "alice"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("Authorization header should be absent when no token configured, got %q", gotAuth)
	}
}

func TestNormalizationClient_RequestBodyContainsClaims(t *testing.T) {
	var receivedClaims map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedClaims)
		_ = json.NewEncoder(w).Encode(shared.Principal{UserID: "alice"})
	}))
	defer srv.Close()

	client := newTestClient(t, srv, "")
	claims := map[string]any{"sub": "alice", "email": "alice@corp.com"}
	_, err := client.Normalize(context.Background(), claims)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedClaims["sub"] != "alice" {
		t.Errorf("sub claim = %v, want alice", receivedClaims["sub"])
	}
	if receivedClaims["email"] != "alice@corp.com" {
		t.Errorf("email claim = %v, want alice@corp.com", receivedClaims["email"])
	}
}

func TestNormalizationClient_Non200StatusIsError(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"400 Bad Request", http.StatusBadRequest},
		{"401 Unauthorized", http.StatusUnauthorized},
		{"500 Internal Server Error", http.StatusInternalServerError},
		{"503 Service Unavailable", http.StatusServiceUnavailable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			client := newTestClient(t, srv, "")
			_, err := client.Normalize(context.Background(), map[string]any{"sub": "alice"})
			if err == nil {
				t.Fatalf("expected error for status %d, got nil", tc.status)
			}
			if !strings.Contains(err.Error(), "unexpected status") {
				t.Errorf("error = %q, want 'unexpected status'", err.Error())
			}
		})
	}
}

func TestNormalizationClient_OversizeRequestIsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(shared.Principal{UserID: "alice"})
	}))
	defer srv.Close()

	cfg := cfgloader.NormalizationPeerConfig{MaxPayloadKB: 1} // 1 KB limit
	cfg.Endpoint = srv.URL
	client, _ := newNormalizationClient(cfg, cfgloader.ModeDev)

	// Build a claims map that exceeds 1 KB when marshalled.
	claims := map[string]any{"data": strings.Repeat("x", 1025)}
	_, err := client.Normalize(context.Background(), claims)
	if err == nil {
		t.Fatal("expected error for oversize request payload, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error = %q, want 'exceeds limit'", err.Error())
	}
}

func TestNormalizationClient_OversizeResponseIsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write more than 1 KB of JSON.
		_, _ = io.WriteString(w, `{"user_id":"`+strings.Repeat("a", 1025)+`"}`)
	}))
	defer srv.Close()

	cfg := cfgloader.NormalizationPeerConfig{MaxPayloadKB: 1}
	cfg.Endpoint = srv.URL
	client, _ := newNormalizationClient(cfg, cfgloader.ModeDev)

	_, err := client.Normalize(context.Background(), map[string]any{"sub": "alice"})
	if err == nil {
		t.Fatal("expected error for oversize response payload, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("error = %q, want 'exceeds limit'", err.Error())
	}
}

func TestNormalizationClient_InvalidJSONResponseIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "not valid json{{{")
	}))
	defer srv.Close()

	client := newTestClient(t, srv, "")
	_, err := client.Normalize(context.Background(), map[string]any{"sub": "alice"})
	if err == nil {
		t.Fatal("expected error for invalid JSON response, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("error = %q, want 'unmarshal'", err.Error())
	}
}

func TestNewNormalizationClient_ProductionRejectsHTTP(t *testing.T) {
	cfg := cfgloader.NormalizationPeerConfig{}
	cfg.Endpoint = "http://mapper.internal/map"
	_, err := newNormalizationClient(cfg, cfgloader.ModeProduction)
	if err == nil {
		t.Fatal("expected error for http:// endpoint in production mode, got nil")
	}
	if !strings.Contains(err.Error(), "https://") {
		t.Errorf("error = %q, should mention https://", err.Error())
	}
}

func TestNewNormalizationClient_ProductionAcceptsHTTPS(t *testing.T) {
	cfg := cfgloader.NormalizationPeerConfig{}
	cfg.Endpoint = "https://mapper.internal/map"
	_, err := newNormalizationClient(cfg, cfgloader.ModeProduction)
	if err != nil {
		t.Fatalf("unexpected error for https:// endpoint in production mode: %v", err)
	}
}

func TestNewNormalizationClient_DevAcceptsHTTP(t *testing.T) {
	cfg := cfgloader.NormalizationPeerConfig{}
	cfg.Endpoint = "http://localhost/map"
	_, err := newNormalizationClient(cfg, cfgloader.ModeDev)
	if err != nil {
		t.Fatalf("unexpected error for http:// endpoint in dev mode: %v", err)
	}
}

func TestNewNormalizationClient_AuthTypeEnforcement(t *testing.T) {
	tests := []struct {
		name        string
		authType    string
		token       string
		errContains string
	}{
		{
			name:     "empty auth type treated as none",
			authType: "",
		},
		{
			name:     "explicit none",
			authType: "none",
		},
		{
			name:     "bearer with token",
			authType: "bearer",
			token:    "tok",
		},
		{
			name:        "bearer without token",
			authType:    "bearer",
			errContains: "bearer_token is required",
		},
		{
			name:        "mtls rejected",
			authType:    "mtls",
			errContains: "not supported for webhook peers",
		},
		{
			name:        "unknown type rejected",
			authType:    "api-key",
			errContains: "not valid",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfgloader.NormalizationPeerConfig{}
			cfg.Endpoint = "http://localhost/map"
			cfg.Auth.Type = tc.authType
			cfg.Auth.Credentials.BearerToken = tc.token
			_, err := newNormalizationClient(cfg, cfgloader.ModeDev)
			if tc.errContains == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error = %q, want contains %q", err.Error(), tc.errContains)
				}
			}
		})
	}
}

func TestNormalizationClient_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until the client cancels.
		<-r.Context().Done()
	}))
	defer srv.Close()

	client := newTestClient(t, srv, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := client.Normalize(ctx, map[string]any{"sub": "alice"})
	if err == nil {
		t.Fatal("expected error after context cancellation, got nil")
	}
}
