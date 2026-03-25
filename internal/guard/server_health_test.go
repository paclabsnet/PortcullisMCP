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
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---- /healthz ---------------------------------------------------------------

func TestGuardHandleHealthz(t *testing.T) {
	s := makeServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.handleHealthz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("status = %q, want %q", result["status"], "ok")
	}
}

// ---- /readyz ----------------------------------------------------------------

func TestGuardHandleReadyz_Ready(t *testing.T) {
	s := makeServer(t)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	s.handleReadyz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["status"] != "ready" {
		t.Errorf("status = %q, want %q", result["status"], "ready")
	}
}

func TestGuardHandleReadyz_MissingKeys(t *testing.T) {
	s := makeServer(t)
	s.keepKey = nil // simulate missing key

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	s.handleReadyz(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["status"] != "unavailable" {
		t.Errorf("status = %q, want %q", result["status"], "unavailable")
	}
}

func TestGuardHandleReadyz_MissingTemplates(t *testing.T) {
	s := makeServer(t)
	s.templates = nil // simulate templates not loaded

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	s.handleReadyz(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestGuardHandleReadyz_EmptyTemplates(t *testing.T) {
	s := makeServer(t)
	s.templates = template.New("") // non-nil but empty (required templates missing)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	s.handleReadyz(w, req)

	// templates != nil, so readyz passes — the template presence check is
	// enforced at startup by loadTemplates, not at runtime.
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
