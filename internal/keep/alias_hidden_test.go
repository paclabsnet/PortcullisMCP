package keep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// aliasTestRouter returns a Router whose "backend" has the given alias map
// (alias -> real name), and a "plain" backend with no aliases.
func aliasTestRouter(aliasToReal map[string]string) *Router {
	r := NewRouter([]BackendConfig{})
	r.mu.Lock()
	r.backends["backend"] = &backendConn{
		cfg:         BackendConfig{Name: "backend", Type: "stdio", Command: "echo"},
		aliasToReal: aliasToReal,
	}
	r.backends["plain"] = &backendConn{
		cfg: BackendConfig{Name: "plain", Type: "stdio", Command: "echo"},
	}
	r.mu.Unlock()
	return r
}

func TestRouter_IsHiddenToolName(t *testing.T) {
	aliases := map[string]string{"safe_delete": "delete_x"}
	tests := []struct {
		name    string
		aliases map[string]string
		server  string
		tool    string
		want    bool
	}{
		{"alias is not hidden", aliases, "backend", "safe_delete", false},
		{"real name of aliased tool is hidden", aliases, "backend", "delete_x", true},
		{"unaliased tool is not hidden", aliases, "backend", "list_x", false},
		{"backend without aliases unchanged", nil, "backend", "delete_x", false},
		{"other backend without aliases unchanged", aliases, "plain", "delete_x", false},
		{"unknown backend unchanged", aliases, "nope", "delete_x", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := aliasTestRouter(tc.aliases)
			if got := r.IsHiddenToolName(tc.server, tc.tool); got != tc.want {
				t.Errorf("IsHiddenToolName(%q,%q) = %v, want %v", tc.server, tc.tool, got, tc.want)
			}
		})
	}
}

func TestRouter_CallTool_RejectsRealNameOfAliasedTool(t *testing.T) {
	r := aliasTestRouter(map[string]string{"safe_delete": "delete_x"})
	_, err := r.CallTool(context.Background(), "backend", "delete_x", nil)
	if !errors.Is(err, errUnknownTool) {
		t.Fatalf("err = %v, want errUnknownTool", err)
	}
}

// recordingRouter wraps a real Router and records dispatched calls.
type recordingRouter struct {
	*Router
	calls []string
}

func (rr *recordingRouter) CallTool(_ context.Context, _, toolName string, _ map[string]any) (*mcp.CallToolResult, error) {
	rr.calls = append(rr.calls, toolName)
	return &mcp.CallToolResult{}, nil
}

func TestHandleCall_AliasedToolNames(t *testing.T) {
	aliases := map[string]string{"safe_delete": "delete_x"}
	tests := []struct {
		name         string
		aliases      map[string]string
		server       string
		tool         string
		wantStatus   int
		wantPDPCalls int
		wantDispatch bool
	}{
		{"alias works", aliases, "backend", "safe_delete", http.StatusOK, 1, true},
		{"real name of aliased tool rejected", aliases, "backend", "delete_x", http.StatusForbidden, 0, false},
		{"unaliased tool works", aliases, "backend", "list_x", http.StatusOK, 1, true},
		{"backend without aliases unchanged", nil, "backend", "delete_x", http.StatusOK, 1, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pdp := &countingPDP{}
			rr := &recordingRouter{Router: aliasTestRouter(tc.aliases)}
			srv := &Server{
				normalizer:  &passthroughNormalizer{silenced: true},
				pdp:         pdp,
				router:      rr,
				decisionLog: NewDecisionLogger(cfgloader.DecisionLogConfig{Enabled: false}),
			}
			body, _ := json.Marshal(shared.EnrichedMCPRequest{
				ServerName:   tc.server,
				ToolName:     tc.tool,
				UserIdentity: shared.UserIdentity{UserID: "alice", SourceType: "os"},
				TraceID:      "t-1",
			})
			w := httptest.NewRecorder()
			srv.handleCall(w, httptest.NewRequest("POST", "/call", bytes.NewReader(body)))

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %s)", w.Code, tc.wantStatus, w.Body.String())
			}
			if pdp.calls != tc.wantPDPCalls {
				t.Errorf("PDP calls = %d, want %d", pdp.calls, tc.wantPDPCalls)
			}
			if dispatched := len(rr.calls) > 0; dispatched != tc.wantDispatch {
				t.Errorf("dispatched = %v, want %v", dispatched, tc.wantDispatch)
			}
		})
	}
}

type countingPDP struct{ calls int }

func (c *countingPDP) GetStaticPolicy(_ context.Context, _ string) (json.RawMessage, error) {
	return json.RawMessage("{}"), nil
}

func (c *countingPDP) Evaluate(_ context.Context, _ AuthorizedRequest) (shared.PDPResponse, error) {
	c.calls++
	return shared.PDPResponse{Decision: "allow"}, nil
}
