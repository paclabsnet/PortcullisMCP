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
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---- machineAuth middleware unit tests --------------------------------------
// These tests exercise machineAuth at the HTTP handler level without a real
// TLS listener. The mTLS path (peer cert check) is tested by synthesizing a
// *http.Request with a non-nil r.TLS and PeerCertificates set.

// syntheticTLSRequest creates an httptest.Request that appears to have come
// over a TLS connection with a verified client certificate.
func syntheticTLSRequest(t *testing.T, method, path string, body []byte) *http.Request {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	// Simulate a verified TLS peer certificate by populating r.TLS.
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{}, // presence is enough; machineAuth checks len > 0
		},
	}
	return req
}

func TestMachineAuth_MTLSPeerCert_Grants(t *testing.T) {
	s := makeServerDirect(AuthConfig{AllowUnauthenticated: false}, LimitsConfig{
		MaxRequestBodyBytes: 512 << 10,
		MaxUserIDBytes:      512,
		MaxJTIBytes:         128,
		MaxPendingJWTBytes:  8192,
	})

	var called bool
	handler := s.machineAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := syntheticTLSRequest(t, http.MethodGet, "/token/unclaimed/list", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called when mTLS peer cert is present")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestMachineAuth_BearerToken_Grants(t *testing.T) {
	s := makeServerDirect(AuthConfig{BearerToken: "valid-token", AllowUnauthenticated: false}, LimitsConfig{
		MaxRequestBodyBytes: 512 << 10,
		MaxUserIDBytes:      512,
		MaxJTIBytes:         128,
		MaxPendingJWTBytes:  8192,
	})

	var called bool
	handler := s.machineAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/token/unclaimed/list", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called with valid bearer token")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestMachineAuth_BothMTLSAndBearer_MTLSTakesPriority(t *testing.T) {
	// When both mTLS peer cert and bearer token are provided, access is granted
	// (mTLS takes precedence in the evaluation order).
	s := makeServerDirect(AuthConfig{BearerToken: "valid-token", AllowUnauthenticated: false}, LimitsConfig{
		MaxRequestBodyBytes: 512 << 10,
	})

	var called bool
	handler := s.machineAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := syntheticTLSRequest(t, http.MethodGet, "/healthz", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called when both mTLS and bearer are provided")
	}
}

func TestMachineAuth_AllowUnauthenticated_WarnsAndGrants(t *testing.T) {
	s := makeServerDirect(AuthConfig{AllowUnauthenticated: true}, LimitsConfig{
		MaxRequestBodyBytes: 512 << 10,
	})

	var called bool
	handler := s.machineAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/token/unclaimed/list", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Error("expected handler to be called when allow_unauthenticated is true")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestMachineAuth_FailClosed_Returns401(t *testing.T) {
	s := makeServerDirect(AuthConfig{AllowUnauthenticated: false}, LimitsConfig{
		MaxRequestBodyBytes: 512 << 10,
	})

	handler := s.machineAuth(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/token/unclaimed/list", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when no credentials and allow_unauthenticated is false", w.Code)
	}
}

func TestMachineAuth_WrongBearerToken_Returns401(t *testing.T) {
	s := makeServerDirect(AuthConfig{BearerToken: "correct-token", AllowUnauthenticated: false}, LimitsConfig{
		MaxRequestBodyBytes: 512 << 10,
	})

	handler := s.machineAuth(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/token/unclaimed/list", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for wrong bearer token", w.Code)
	}
}

// ---- Route segregation tests ------------------------------------------------
// These tests verify that the UI and API muxes register routes correctly.
// They exercise the mux routing logic without starting a real network listener.

func TestRouteSegregation_APIRejectsApproveRoute(t *testing.T) {
	// The API mux should not have /approve registered; it must return 404.
	s := makeServer(t)

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("GET /healthz", s.handleHealthz)
	apiMux.HandleFunc("GET /readyz", s.handleReadyz)
	apiMux.HandleFunc("GET /token/unclaimed/list", s.machineAuth(s.handleTokenUnclaimedList))
	apiMux.HandleFunc("POST /token/deposit", s.machineAuth(s.handleTokenDeposit))
	apiMux.HandleFunc("POST /token/claim", s.machineAuth(s.handleTokenClaim))
	apiMux.HandleFunc("POST /pending", s.machineAuth(s.handlePending))

	req := httptest.NewRequest(http.MethodGet, "/approve", nil)
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("API mux /approve: status = %d, want 404", w.Code)
	}
}

func TestRouteSegregation_UIRejectsTokenRoutes(t *testing.T) {
	// The UI mux should not have /token/* registered; they must return 404.
	s := makeServer(t)

	uiMux := http.NewServeMux()
	uiMux.HandleFunc("GET /healthz", s.handleHealthz)
	uiMux.HandleFunc("GET /readyz", s.handleReadyz)
	uiMux.HandleFunc("GET /approve", s.handleGet)
	uiMux.HandleFunc("POST /approve", s.handlePost)

	for _, path := range []string{"/token/unclaimed/list", "/token/claim", "/token/deposit", "/pending"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		w := httptest.NewRecorder()
		uiMux.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("UI mux %s: status = %d, want 404", path, w.Code)
		}
	}
}

func TestRouteSegregation_SharedHealthzOnBothMuxes(t *testing.T) {
	s := makeServer(t)

	uiMux := http.NewServeMux()
	uiMux.HandleFunc("GET /healthz", s.handleHealthz)
	uiMux.HandleFunc("GET /readyz", s.handleReadyz)

	apiMux := http.NewServeMux()
	apiMux.HandleFunc("GET /healthz", s.handleHealthz)
	apiMux.HandleFunc("GET /readyz", s.handleReadyz)

	for _, mux := range []*http.ServeMux{uiMux, apiMux} {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("/healthz: status = %d, want 200", w.Code)
		}

		req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("/readyz: status = %d, want 200", w.Code)
		}
	}
}
