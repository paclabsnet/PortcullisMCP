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
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

func TestAdminReload_Unauthorized(t *testing.T) {
	srv := &Server{
		cfg: Config{
			Responsibility: ResponsibilityConfig{
				Admin: AdminConfig{Token: "secret"},
			},
		},
		decisionLog: NewDecisionLogger(cfgloader.DecisionLogConfig{Enabled: false}),
	}

	req := httptest.NewRequest("POST", "/admin/reload", nil)
	// No header
	w := httptest.NewRecorder()

	srv.adminAuthMiddleware(srv.handleReload).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAdminReload_ForbiddenWhenTokenEmpty(t *testing.T) {
	srv := &Server{
		cfg: Config{
			Responsibility: ResponsibilityConfig{
				Admin: AdminConfig{Token: ""},
			},
		},
		decisionLog: NewDecisionLogger(cfgloader.DecisionLogConfig{Enabled: false}),
	}

	req := httptest.NewRequest("POST", "/admin/reload", nil)
	req.Header.Set("X-Api-Key", "anything")
	w := httptest.NewRecorder()

	srv.adminAuthMiddleware(srv.handleReload).ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestAdminReload_Success(t *testing.T) {
	// Create a temp config file for the reload to read.
	tmp, err := os.CreateTemp("", "keep-test-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	content := `
server:
  endpoints:
    main:
      listen: "localhost:8080"
responsibility:
  mcp_backends:
    - name: "reloaded-backend"
      type: "stdio"
      command: "true"
  policy:
    strategy: "noop"
identity:
  strategy: "passthrough"
`
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	router := &mockReloadRouter{}
	srv := &Server{
		cfg: Config{
			Responsibility: ResponsibilityConfig{
				Admin: AdminConfig{Token: "secret"},
			},
		},
		configPath:  tmp.Name(),
		router:      router,
		decisionLog: NewDecisionLogger(cfgloader.DecisionLogConfig{Enabled: false}),
	}

	req := httptest.NewRequest("POST", "/admin/reload", nil)
	req.Header.Set("X-Api-Key", "secret")
	w := httptest.NewRecorder()

	srv.handleReload(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	if !router.reloaded {
		t.Error("router.Reload was not called")
	}
	if len(router.lastBackends) != 1 || router.lastBackends[0].Name != "reloaded-backend" {
		t.Errorf("unexpected backends passed to Reload: %+v", router.lastBackends)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "reloaded" {
		t.Errorf("expected status=reloaded, got %q", resp["status"])
	}
}

func TestAdminReload_ReadConfigError(t *testing.T) {
	srv := &Server{
		cfg: Config{
			Responsibility: ResponsibilityConfig{
				Admin: AdminConfig{Token: "secret"},
			},
		},
		configPath:  "/nonexistent/path/to/keep.yaml",
		decisionLog: NewDecisionLogger(cfgloader.DecisionLogConfig{Enabled: false}),
	}

	req := httptest.NewRequest("POST", "/admin/reload", nil)
	req.Header.Set("X-Api-Key", "secret")
	w := httptest.NewRecorder()

	srv.handleReload(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestAdminReload_RouterReloadError(t *testing.T) {
	tmp, _ := os.CreateTemp("", "keep-test-*.yaml")
	defer os.Remove(tmp.Name())
	tmp.WriteString(`
server:
  endpoints:
    main:
      listen: "localhost:8080"
responsibility:
  mcp_backends: []
  policy:
    strategy: "noop"
identity:
  strategy: "passthrough"
`)
	tmp.Close()

	srv := &Server{
		cfg: Config{
			Responsibility: ResponsibilityConfig{
				Admin: AdminConfig{Token: "secret"},
			},
		},
		configPath: tmp.Name(),
		router:     &mockReloadRouter{err: context.DeadlineExceeded},
		decisionLog: NewDecisionLogger(cfgloader.DecisionLogConfig{Enabled: false}),
	}

	req := httptest.NewRequest("POST", "/admin/reload", nil)
	req.Header.Set("X-Api-Key", "secret")
	w := httptest.NewRecorder()

	srv.handleReload(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

type mockReloadRouter struct {
	reloaded      bool
	lastBackends  []BackendConfig
	err           error
}

func (m *mockReloadRouter) CallTool(_ context.Context, _, _ string, _ map[string]any) (*mcp.CallToolResult, error) {
	return nil, nil
}

func (m *mockReloadRouter) ListAllTools(_ context.Context) ([]shared.AnnotatedTool, error) {
	return nil, nil
}

func (m *mockReloadRouter) Reload(_ context.Context, backends []BackendConfig) error {
	m.reloaded = true
	m.lastBackends = backends
	return m.err
}
