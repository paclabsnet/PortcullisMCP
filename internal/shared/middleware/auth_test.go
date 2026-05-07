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

package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// okHandler is a trivial handler that records it was reached.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func applyAuth(cfg AuthConfig, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	BearerAuth(cfg)(okHandler).ServeHTTP(w, req)
	return w
}

// -------------------------------------------------------------------------
// Bearer token
// -------------------------------------------------------------------------

func TestBearerAuth_ValidToken_Passes(t *testing.T) {
	t.Parallel()
	cfg := AuthConfig{BearerToken: "secret"}
	req := httptest.NewRequest(http.MethodGet, "/call", nil)
	req.Header.Set("Authorization", "Bearer secret")

	w := applyAuth(cfg, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestBearerAuth_WrongToken_Rejects(t *testing.T) {
	t.Parallel()
	cfg := AuthConfig{BearerToken: "secret"}

	cases := []struct {
		name   string
		header string
	}{
		{"wrong token", "Bearer wrong"},
		{"missing prefix", "secret"},
		{"empty header", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/call", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			w := applyAuth(cfg, req)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", w.Code)
			}
			if w.Header().Get("WWW-Authenticate") == "" {
				t.Error("want WWW-Authenticate header in 401 response")
			}
		})
	}
}

func TestBearerAuth_401Body_IsJSON(t *testing.T) {
	t.Parallel()
	cfg := AuthConfig{BearerToken: "secret", Realm: "my-realm"}
	req := httptest.NewRequest(http.MethodGet, "/call", nil)

	w := applyAuth(cfg, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body["error"] == "" {
		t.Error("JSON body missing \"error\" field")
	}
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), "my-realm") {
		t.Errorf("WWW-Authenticate does not contain realm: %q", w.Header().Get("WWW-Authenticate"))
	}
}

// -------------------------------------------------------------------------
// Fail-closed: no auth configured
// -------------------------------------------------------------------------

func TestBearerAuth_NoBearerAndNoMTLS_FailsClosed(t *testing.T) {
	t.Parallel()
	cfg := AuthConfig{} // nothing configured
	req := httptest.NewRequest(http.MethodGet, "/call", nil)

	w := applyAuth(cfg, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (fail-closed)", w.Code)
	}
}

// -------------------------------------------------------------------------
// Skip paths
// -------------------------------------------------------------------------

func TestBearerAuth_SkipPath_Bypasses(t *testing.T) {
	t.Parallel()
	cfg := AuthConfig{
		BearerToken: "secret",
		SkipPaths:   []string{"/healthz", "/readyz"},
	}

	for _, path := range cfg.SkipPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			// No Authorization header — should still pass.
			w := applyAuth(cfg, req)
			if w.Code != http.StatusOK {
				t.Errorf("path %s: status = %d, want 200 (skip path)", path, w.Code)
			}
		})
	}
}

func TestBearerAuth_NonSkipPath_RequiresAuth(t *testing.T) {
	t.Parallel()
	cfg := AuthConfig{
		BearerToken: "secret",
		SkipPaths:   []string{"/healthz"},
	}
	req := httptest.NewRequest(http.MethodGet, "/call", nil)

	w := applyAuth(cfg, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for non-skip path without token", w.Code)
	}
}

// -------------------------------------------------------------------------
// mTLS
// -------------------------------------------------------------------------

func TestBearerAuth_MTLS_PeerCert_Passes(t *testing.T) {
	t.Parallel()
	cfg := AuthConfig{
		ClientCA:    "/etc/ssl/ca.pem", // non-empty = mTLS configured
		BearerToken: "secret",
	}

	req := httptest.NewRequest(http.MethodGet, "/call", nil)
	// Simulate a request that arrived over mTLS with a verified peer cert.
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{}}, // non-empty = cert presented
	}
	// No Bearer token — mTLS alone should suffice.

	w := applyAuth(cfg, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for mTLS peer cert", w.Code)
	}
}

func TestBearerAuth_MTLS_Configured_NoPeerCert_FallsBackToBearer(t *testing.T) {
	t.Parallel()
	cfg := AuthConfig{
		ClientCA:    "/etc/ssl/ca.pem",
		BearerToken: "secret",
	}

	t.Run("valid bearer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/call", nil)
		req.Header.Set("Authorization", "Bearer secret")
		// No TLS — falls back to Bearer check.
		w := applyAuth(cfg, req)
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})

	t.Run("no token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/call", nil)
		w := applyAuth(cfg, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", w.Code)
		}
	})
}

func TestBearerAuth_MTLS_NotConfigured_PeerCertIgnored(t *testing.T) {
	t.Parallel()
	// ClientCA is empty — mTLS is not configured, so a peer cert should not
	// be treated as authentication.
	cfg := AuthConfig{BearerToken: "secret"}

	req := httptest.NewRequest(http.MethodGet, "/call", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{}},
	}
	// No Bearer token — must reject.

	w := applyAuth(cfg, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (mTLS not configured, no Bearer)", w.Code)
	}
}

// -------------------------------------------------------------------------
// Default realm
// -------------------------------------------------------------------------

func TestBearerAuth_DefaultRealm(t *testing.T) {
	t.Parallel()
	cfg := AuthConfig{BearerToken: "secret"} // no Realm set
	req := httptest.NewRequest(http.MethodGet, "/call", nil)

	w := applyAuth(cfg, req)
	wwa := w.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwa, "portcullis") {
		t.Errorf("WWW-Authenticate %q should contain default realm \"portcullis\"", wwa)
	}
}
