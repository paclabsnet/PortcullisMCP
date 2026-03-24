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
	"net/http"
	"net/http/httptest"
	"testing"
)

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
		json.NewEncoder(w).Encode(map[string]string{"status": "registered", "jti": "test-jti"})
	}))
	defer srv.Close()

	g := NewGuardClient(GuardConfig{Endpoint: srv.URL})
	if err := g.RegisterPending(context.Background(), "test-jti", "header.payload.sig"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegisterPending_AuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	g := NewGuardClient(GuardConfig{Endpoint: srv.URL, BearerToken: "wrong"})
	if err := g.RegisterPending(context.Background(), "jti", "jwt"); err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
}

func TestRegisterPending_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal"})
	}))
	defer srv.Close()

	g := NewGuardClient(GuardConfig{Endpoint: srv.URL})
	if err := g.RegisterPending(context.Background(), "jti", "jwt"); err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

func TestRegisterPending_NetworkError(t *testing.T) {
	g := NewGuardClient(GuardConfig{Endpoint: "http://127.0.0.1:1"})
	if err := g.RegisterPending(context.Background(), "jti", "jwt"); err == nil {
		t.Fatal("expected network error, got nil")
	}
}

func TestRegisterPending_BearerTokenSent(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "registered", "jti": "j"})
	}))
	defer srv.Close()

	g := NewGuardClient(GuardConfig{Endpoint: srv.URL, BearerToken: "my-secret"})
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
		json.NewEncoder(w).Encode(map[string]string{"status": "registered", "jti": "j"})
	}))
	defer srv.Close()

	g := NewGuardClient(GuardConfig{Endpoint: srv.URL}) // no bearer token
	_ = g.RegisterPending(context.Background(), "j", "jwt")

	if gotAuth != "" {
		t.Errorf("expected no Authorization header, got %q", gotAuth)
	}
}
