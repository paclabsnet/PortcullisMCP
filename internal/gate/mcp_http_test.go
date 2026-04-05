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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func newTestMCPHTTPHandler(t *testing.T) *MCPHTTPHandler {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "test-gate", Version: "0.0.0"}, nil)
	return NewMCPHTTPHandler(srv, nil)
}

func TestMCPHTTPHealthChecks(t *testing.T) {
	h := newTestMCPHTTPHandler(t)

	for _, path := range []string{"/healthz", "/readyz"} {
		t.Run(path+" returns 200 OK", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("GET %s: status = %d, want %d", path, rr.Code, http.StatusOK)
			}
			if body := rr.Body.String(); body != "ok" {
				t.Errorf("GET %s: body = %q, want %q", path, body, "ok")
			}
		})

		t.Run(path+" returns 200 OK for POST too", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("POST %s: status = %d, want %d", path, rr.Code, http.StatusOK)
			}
		})
	}

	t.Run("non-health path is not intercepted by health handler", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		// The SDK handler will respond; we just verify it is NOT 200/ok from health.
		body := rr.Body.String()
		if body == "ok" {
			t.Error("/mcp should not return the health-check body")
		}
	})
}
