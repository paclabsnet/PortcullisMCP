package keep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
	// Derive the hidden set from the alias map (inverse of buildAliasIndex input).
	toolMap := make(map[string]string, len(aliasToReal))
	for alias, real := range aliasToReal {
		toolMap[real] = alias
	}
	_, r.backends["backend"].hiddenNames = buildAliasIndex(toolMap)
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

func TestBuildAliasIndex(t *testing.T) {
	tests := []struct {
		name       string
		toolMap    map[string]string // real -> alias
		wantHidden []string
		wantNil    bool
	}{
		{"empty", nil, nil, true},
		{"simple", map[string]string{"delete_x": "safe_delete"}, []string{"delete_x"}, false},
		{"real name that is another alias is not hidden",
			map[string]string{"a": "b", "b": "c"}, []string{"a"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a2r, hidden := buildAliasIndex(tc.toolMap)
			if tc.wantNil {
				if a2r != nil || hidden != nil {
					t.Fatalf("want nil results, got %v %v", a2r, hidden)
				}
				return
			}
			if len(hidden) != len(tc.wantHidden) {
				t.Fatalf("hidden = %v, want %v", hidden, tc.wantHidden)
			}
			for _, n := range tc.wantHidden {
				if _, ok := hidden[n]; !ok {
					t.Errorf("%q not hidden", n)
				}
			}
		})
	}
}

func TestSanitizeForLog(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"plain", "oidc", `"oidc"`},
		{"newline escaped", "a\nb", `"a\nb"`},
		{"truncated", strings.Repeat("x", 100), `"` + strings.Repeat("x", 32) + `..."`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeForLog(tc.in); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestVerifyingNormalizers_DoNotReflectSourceType(t *testing.T) {
	const evil = "<script>evil-source</script>"
	norms := map[string]IdentityNormalizer{
		"hmac": &hmacVerifyingNormalizer{},
		"oidc": &oidcVerifyingNormalizer{},
	}
	for name, n := range norms {
		t.Run(name, func(t *testing.T) {
			_, err := n.Normalize(context.Background(), shared.UserIdentity{SourceType: evil})
			var ive *shared.IdentityVerificationError
			if !errors.As(err, &ive) {
				t.Fatalf("err = %v, want IdentityVerificationError", err)
			}
			if strings.Contains(err.Error(), "evil-source") {
				t.Errorf("error reflects client value: %q", err.Error())
			}
		})
	}
}
