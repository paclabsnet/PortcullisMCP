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

package gate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// mustGuardClient creates a GuardClient for testing, failing the test on error.
func mustGuardClient(t *testing.T, cfg GuardConfig) *GuardClient {
	t.Helper()
	g, err := NewGuardClient(cfg)
	if err != nil {
		t.Fatalf("NewGuardClient: %v", err)
	}
	return g
}

// ---- RegisterPending --------------------------------------------------------

func TestRegisterPending_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pending" {
			t.Errorf("path = %q, want /pending", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		var body struct {
			JTI string `json:"jti"`
			JWT string `json:"jwt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if body.JTI != "test-jti" {
			t.Errorf("jti = %q, want test-jti", body.JTI)
		}
		if body.JWT != "header.payload.sig" {
			t.Errorf("jwt = %q, want header.payload.sig", body.JWT)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "registered", "jti": "test-jti"})
	}))
	defer srv.Close()

	g := mustGuardClient(t, GuardConfig{
		GuardPeerConfig: cfgloader.GuardPeerConfig{
			Endpoints: cfgloader.GuardEndpoints{TokenAPI: srv.URL},
		},
	})
	if err := g.RegisterPending(context.Background(), "test-jti", "header.payload.sig"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegisterPending_AuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	g := mustGuardClient(t, GuardConfig{
		GuardPeerConfig: cfgloader.GuardPeerConfig{
			Endpoints: cfgloader.GuardEndpoints{TokenAPI: srv.URL},
			PeerAuth: cfgloader.PeerAuth{
				Auth: cfgloader.AuthSettings{
					Credentials: cfgloader.AuthCredentials{BearerToken: "wrong"},
				},
			},
		},
	})
	if err := g.RegisterPending(context.Background(), "jti", "jwt"); err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
}

func TestRegisterPending_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal"})
	}))
	defer srv.Close()

	g := mustGuardClient(t, GuardConfig{
		GuardPeerConfig: cfgloader.GuardPeerConfig{
			Endpoints: cfgloader.GuardEndpoints{TokenAPI: srv.URL},
		},
	})
	if err := g.RegisterPending(context.Background(), "jti", "jwt"); err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

func TestRegisterPending_NetworkError(t *testing.T) {
	g := mustGuardClient(t, GuardConfig{
		GuardPeerConfig: cfgloader.GuardPeerConfig{
			Endpoints: cfgloader.GuardEndpoints{TokenAPI: "http://127.0.0.1:1"},
		},
	})
	if err := g.RegisterPending(context.Background(), "jti", "jwt"); err == nil {
		t.Fatal("expected network error, got nil")
	}
}

func TestRegisterPending_BearerTokenSent(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "registered", "jti": "j"})
	}))
	defer srv.Close()

	g := mustGuardClient(t, GuardConfig{
		GuardPeerConfig: cfgloader.GuardPeerConfig{
			Endpoints: cfgloader.GuardEndpoints{TokenAPI: srv.URL},
			PeerAuth: cfgloader.PeerAuth{
				Auth: cfgloader.AuthSettings{
					Credentials: cfgloader.AuthCredentials{BearerToken: "my-secret"},
				},
			},
		},
	})
	_ = g.RegisterPending(context.Background(), "j", "jwt")

	if gotAuth != "Bearer my-secret" {
		t.Errorf("Authorization = %q, want Bearer my-secret", gotAuth)
	}
}

func TestRegisterPending_NoBearerTokenWhenNotConfigured(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "registered", "jti": "j"})
	}))
	defer srv.Close()

	g := mustGuardClient(t, GuardConfig{
		GuardPeerConfig: cfgloader.GuardPeerConfig{
			Endpoints: cfgloader.GuardEndpoints{TokenAPI: srv.URL},
		},
	}) // no bearer token
	_ = g.RegisterPending(context.Background(), "j", "jwt")

	if gotAuth != "" {
		t.Errorf("expected no Authorization header, got %q", gotAuth)
	}
}

// ---- ClaimToken -------------------------------------------------------------

func TestClaimToken_Success(t *testing.T) {
	const wantRaw = "header.payload.sig"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token/claim" {
			t.Errorf("path = %q, want /token/claim", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		var body struct {
			JTI string `json:"jti"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if body.JTI != "claim-jti" {
			t.Errorf("jti = %q, want claim-jti", body.JTI)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"raw": wantRaw})
	}))
	defer srv.Close()

	g := mustGuardClient(t, GuardConfig{
		GuardPeerConfig: cfgloader.GuardPeerConfig{
			Endpoints: cfgloader.GuardEndpoints{TokenAPI: srv.URL},
		},
	})
	raw, err := g.ClaimToken(context.Background(), "claim-jti")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != wantRaw {
		t.Errorf("raw = %q, want %q", raw, wantRaw)
	}
}

func TestClaimToken_NotFound_ReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	g := mustGuardClient(t, GuardConfig{
		GuardPeerConfig: cfgloader.GuardPeerConfig{
			Endpoints: cfgloader.GuardEndpoints{TokenAPI: srv.URL},
		},
	})
	raw, err := g.ClaimToken(context.Background(), "unknown-jti")
	if err != nil {
		t.Fatalf("404 should return nil error, got: %v", err)
	}
	if raw != "" {
		t.Errorf("404 should return empty raw, got %q", raw)
	}
}

func TestClaimToken_ServerError_ReturnsGuardAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
	}))
	defer srv.Close()

	g := mustGuardClient(t, GuardConfig{
		GuardPeerConfig: cfgloader.GuardPeerConfig{
			Endpoints: cfgloader.GuardEndpoints{TokenAPI: srv.URL},
		},
	})
	_, err := g.ClaimToken(context.Background(), "jti-err")
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
	var apiErr *GuardAPIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *GuardAPIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want 500", apiErr.StatusCode)
	}
}

func TestClaimToken_NetworkError(t *testing.T) {
	g := mustGuardClient(t, GuardConfig{
		GuardPeerConfig: cfgloader.GuardPeerConfig{
			Endpoints: cfgloader.GuardEndpoints{TokenAPI: "http://127.0.0.1:1"},
		},
	})
	_, err := g.ClaimToken(context.Background(), "jti")
	if err == nil {
		t.Fatal("expected network error, got nil")
	}
}

func TestClaimToken_BearerTokenSent(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]string{"raw": "tok"})
	}))
	defer srv.Close()

	g := mustGuardClient(t, GuardConfig{
		GuardPeerConfig: cfgloader.GuardPeerConfig{
			Endpoints: cfgloader.GuardEndpoints{TokenAPI: srv.URL},
			PeerAuth: cfgloader.PeerAuth{
				Auth: cfgloader.AuthSettings{
					Credentials: cfgloader.AuthCredentials{BearerToken: "gate-secret"},
				},
			},
		},
	})
	_, _ = g.ClaimToken(context.Background(), "j")
	if gotAuth != "Bearer gate-secret" {
		t.Errorf("Authorization = %q, want Bearer gate-secret", gotAuth)
	}
}
