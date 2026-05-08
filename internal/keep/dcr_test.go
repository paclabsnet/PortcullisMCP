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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newDCROAuthConfig returns a minimal BackendOAuth suitable for DCR tests.
func newDCROAuthConfig(registrationEndpoint string) *BackendOAuth {
	return &BackendOAuth{
		CallbackURL: "https://keep.example.com/oauth/callback",
		Scopes:      []string{"openid", "profile"},
		DCR: BackendDCR{
			Enabled:              true,
			RegistrationEndpoint: registrationEndpoint,
			ClientName:           "Portcullis Keep",
		},
	}
}

func TestRegisterDynamicClient_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", ct)
		}

		var req dcrRegistrationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if len(req.RedirectURIs) == 0 || req.RedirectURIs[0] != "https://keep.example.com/oauth/callback" {
			t.Errorf("unexpected redirect_uris: %v", req.RedirectURIs)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(dcrRegistrationResponse{
			ClientID:                "dynamic-client-id",
			ClientSecret:            "dynamic-secret",
			ClientSecretExpiresAt:   0,
			TokenEndpointAuthMethod: "client_secret_basic",
			Scope:                   "openid profile",
		})
	}))
	defer srv.Close()

	cfg := newDCROAuthConfig(srv.URL)
	reg, err := RegisterDynamicClient(context.Background(), srv.Client(), cfg)
	if err != nil {
		t.Fatalf("RegisterDynamicClient: %v", err)
	}
	if reg.ClientID != "dynamic-client-id" {
		t.Errorf("ClientID: want dynamic-client-id, got %q", reg.ClientID)
	}
	if reg.ClientSecret != "dynamic-secret" {
		t.Errorf("ClientSecret: want dynamic-secret, got %q", reg.ClientSecret)
	}
	if reg.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("TokenEndpointAuthMethod: want client_secret_basic, got %q", reg.TokenEndpointAuthMethod)
	}
	if reg.Scopes != "openid profile" {
		t.Errorf("Scopes: want 'openid profile', got %q", reg.Scopes)
	}
}

func TestRegisterDynamicClient_InitialAccessToken(t *testing.T) {
	const wantIAT = "super-secret-iat"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+wantIAT {
			t.Errorf("expected Authorization: Bearer %s, got %q", wantIAT, auth)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(dcrRegistrationResponse{
			ClientID: "cid",
		})
	}))
	defer srv.Close()

	cfg := newDCROAuthConfig(srv.URL)
	cfg.DCR.InitialAccessToken = wantIAT
	if _, err := RegisterDynamicClient(context.Background(), srv.Client(), cfg); err != nil {
		t.Fatalf("RegisterDynamicClient: %v", err)
	}
}

func TestRegisterDynamicClient_SoftwareStatement(t *testing.T) {
	const wantSS = "eyJhbGciOiJSUzI1NiJ9.e30.sig"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req dcrRegistrationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.SoftwareStatement != wantSS {
			t.Errorf("software_statement: want %q, got %q", wantSS, req.SoftwareStatement)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(dcrRegistrationResponse{ClientID: "cid"})
	}))
	defer srv.Close()

	cfg := newDCROAuthConfig(srv.URL)
	cfg.DCR.SoftwareStatement = wantSS
	if _, err := RegisterDynamicClient(context.Background(), srv.Client(), cfg); err != nil {
		t.Fatalf("RegisterDynamicClient: %v", err)
	}
}

func TestRegisterDynamicClient_RefreshTokenGrantType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req dcrRegistrationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		hasRefresh := false
		for _, g := range req.GrantTypes {
			if g == "refresh_token" {
				hasRefresh = true
			}
		}
		if !hasRefresh {
			t.Errorf("expected refresh_token in grant_types, got %v", req.GrantTypes)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(dcrRegistrationResponse{ClientID: "cid"})
	}))
	defer srv.Close()

	cfg := newDCROAuthConfig(srv.URL)
	cfg.StoreRefreshTokens = true
	if _, err := RegisterDynamicClient(context.Background(), srv.Client(), cfg); err != nil {
		t.Fatalf("RegisterDynamicClient: %v", err)
	}
}

func TestRegisterDynamicClient_IdPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dcrRegistrationResponse{
			Error:            "invalid_software_statement",
			ErrorDescription: "The software statement is invalid",
		})
	}))
	defer srv.Close()

	cfg := newDCROAuthConfig(srv.URL)
	_, err := RegisterDynamicClient(context.Background(), srv.Client(), cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid_software_statement") {
		t.Errorf("error should mention the IdP error code, got: %v", err)
	}
}

func TestRegisterDynamicClient_NotFound_ReturnsErrDCRNotSupported(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()

			cfg := newDCROAuthConfig(srv.URL)
			_, err := RegisterDynamicClient(context.Background(), srv.Client(), cfg)
			if !errors.Is(err, ErrDCRNotSupported) {
				t.Errorf("expected ErrDCRNotSupported for status %d, got: %v", status, err)
			}
		})
	}
}

func TestRegisterDynamicClient_MissingClientID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(dcrRegistrationResponse{ClientID: ""}) // missing client_id
	}))
	defer srv.Close()

	cfg := newDCROAuthConfig(srv.URL)
	_, err := RegisterDynamicClient(context.Background(), srv.Client(), cfg)
	if err == nil || !strings.Contains(err.Error(), "client_id") {
		t.Errorf("expected error about missing client_id, got: %v", err)
	}
}

func TestRegisterDynamicClient_AuthMethodFallback(t *testing.T) {
	// IdP returns no token_endpoint_auth_method — should default to client_secret_basic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(dcrRegistrationResponse{
			ClientID: "cid",
			// TokenEndpointAuthMethod intentionally omitted
		})
	}))
	defer srv.Close()

	cfg := newDCROAuthConfig(srv.URL)
	reg, err := RegisterDynamicClient(context.Background(), srv.Client(), cfg)
	if err != nil {
		t.Fatalf("RegisterDynamicClient: %v", err)
	}
	if reg.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("expected fallback to client_secret_basic, got %q", reg.TokenEndpointAuthMethod)
	}
}

func TestRegisterDynamicClient_TimeoutRespected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // longer than the configured timeout
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	cfg := newDCROAuthConfig(srv.URL)
	cfg.DCR.Timeout = 10 * time.Millisecond // very short

	_, err := RegisterDynamicClient(context.Background(), srv.Client(), cfg)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestScopeDifference(t *testing.T) {
	tests := []struct {
		want    []string
		have    []string
		missing []string
	}{
		{[]string{"openid", "profile"}, []string{"openid", "profile"}, nil},
		{[]string{"openid", "profile", "email"}, []string{"openid"}, []string{"profile", "email"}},
		{[]string{}, []string{"openid"}, nil},
	}
	for _, tt := range tests {
		got := scopeDifference(tt.want, tt.have)
		if len(got) != len(tt.missing) {
			t.Errorf("scopeDifference(%v, %v): want %v, got %v", tt.want, tt.have, tt.missing, got)
		}
	}
}
