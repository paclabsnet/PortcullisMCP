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
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/paclabsnet/PortcullisMCP/internal/gate/localfs"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
	"github.com/stretchr/testify/assert"
)

type mockIdentitySource struct {
	identity shared.UserIdentity
}

func (m *mockIdentitySource) Get(_ context.Context) shared.UserIdentity {
	return m.identity
}
func (m *mockIdentitySource) SetToken(_ string) error {
	return nil
}
func (m *mockIdentitySource) Clear() {}

type mockForwarder struct {
	callToolFunc  func(ctx context.Context, req shared.EnrichedMCPRequest) (*mcp.CallToolResult, error)
	authorizeFunc func(ctx context.Context, req shared.EnrichedMCPRequest) error
	ListToolsFunc func(ctx context.Context, id shared.UserIdentity, tokens []shared.EscalationToken) ([]shared.AnnotatedTool, error)
}

func (m *mockForwarder) CallTool(ctx context.Context, req shared.EnrichedMCPRequest) (*mcp.CallToolResult, error) {
	if m.callToolFunc != nil {
		return m.callToolFunc(ctx, req)
	}
	return nil, nil
}
func (m *mockForwarder) Authorize(ctx context.Context, req shared.EnrichedMCPRequest) error {
	if m.authorizeFunc != nil {
		return m.authorizeFunc(ctx, req)
	}
	return nil
}
func (m *mockForwarder) ListTools(ctx context.Context, id shared.UserIdentity, tokens []shared.EscalationToken) ([]shared.AnnotatedTool, error) {
	if m.ListToolsFunc != nil {
		return m.ListToolsFunc(ctx, id, tokens)
	}
	return nil, nil
}
func (m *mockForwarder) SendLogs(_ context.Context, _ []DecisionLogEntry) error {
	return nil
}
func (m *mockForwarder) GetStaticPolicy(_ context.Context, _ string) (json.RawMessage, error) {
	return json.RawMessage("{}"), nil
}

type mockForwarderWithSendLogs struct {
	mockForwarder
	sendLogsFunc func(ctx context.Context, entries []DecisionLogEntry) error
}

func (m *mockForwarderWithSendLogs) SendLogs(ctx context.Context, entries []DecisionLogEntry) error {
	if m.sendLogsFunc != nil {
		return m.sendLogsFunc(ctx, entries)
	}
	return nil
}

func TestHandleToolCall_OIDC_Enforcement(t *testing.T) {
	tests := []struct {
		name          string
		state         GateState
		expectedError string
	}{
		{
			name:          "Unauthenticated",
			state:         StateUnauthenticated,
			expectedError: "Authentication required",
		},
		{
			name:          "Authenticating",
			state:         StateAuthenticating,
			expectedError: "Please complete the login process",
		},
		{
			name:          "SystemError",
			state:         StateSystemError,
			expectedError: "Portcullis Gate is having trouble",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewStateMachine()
			switch tt.state {
			case StateUnauthenticated:
				sm.SetUnauthenticated()
			case StateAuthenticating:
				sm.SetAuthenticating()
			case StateSystemError:
				sm.SetSystemError(SubstateInvalid, "test error", "detail")
			}

			g := &Gate{
				cfg: Config{
					Identity: IdentityConfig{Strategy: "oidc-login"},
				},
				stateMachine: sm,
				identity:     &mockIdentitySource{},
			}

			res, err := g.handleToolCall(context.Background(), "some_tool", nil)
			if err != nil {
				t.Fatalf("handleToolCall returned unexpected error: %v", err)
			}
			if !res.IsError {
				t.Error("expected error result for non-authenticated state")
			}
			tc := res.Content[0].(*mcp.TextContent)
			if !strings.Contains(tc.Text, tt.expectedError) {
				t.Errorf("expected error containing %q, got %q", tt.expectedError, tc.Text)
			}
		})
	}
}

func TestHandleToolCall_Success(t *testing.T) {
	idSource := &mockIdentitySource{
		identity: shared.UserIdentity{UserID: "test-user"},
	}
	fwd := &mockForwarder{
		callToolFunc: func(ctx context.Context, req shared.EnrichedMCPRequest) (*mcp.CallToolResult, error) {
			if req.UserIdentity.UserID != "test-user" {
				return nil, errors.New("wrong user id")
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "ok"}},
			}, nil
		},
	}

	g := &Gate{
		cfg: Config{
			Identity: IdentityConfig{Strategy: "os"},
		},
		identity:      idSource,
		forwarder:     fwd,
		toolServerMap: map[string]string{"test_tool": "test-server"},
		sessionID:     "test-session",
		escalations:   &mockTokenStore{},
		escalationMgr: NewEscalationManager(nil, NewInMemoryPendingStore(), &mockTokenStore{}, EscalationConfig{}, NewSingleTenantProvider(nil, ""), idSource, ""),
		logger:        &captureLogger{},
	}

	res, err := g.handleToolCall(context.Background(), "test_tool", map[string]any{"arg1": "val1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected no error in result, got: %v", res.Content)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if text != "ok" {
		t.Errorf("expected 'ok', got %q", text)
	}
}

func TestHandleToolCall_FastPath_Allow(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "hello.txt")
	_ = os.WriteFile(testFile, []byte("world"), 0644)

	_, localSession, err := localfs.Connect(context.Background(), []string{tmpDir})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	captured := &captureLogger{}
	g := &Gate{
		cfg: Config{
			Responsibility: ResponsibilityConfig{
				Tools: ToolsConfig{
					LocalFS: LocalFSConfig{
						Workspace: SandboxConfig{Directory: tmpDir},
						Strategy:  LocalFSStrategyConfig{Read: "allow"},
					},
				},
			},
		},
		localFS:   localSession,
		identity:  &mockIdentitySource{},
		sessionID: "test-session",
		logger:    captured,
	}

	res, err := g.handleToolCall(context.Background(), "read_text_file", map[string]any{"path": testFile})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected no error in result, got: %v", res.Content)
	}

	entries := captured.all()
	if len(entries) == 0 {
		t.Fatal("expected a log entry")
	}
	if entries[0].Decision != "allow" || entries[0].Reason != "sandbox" {
		t.Errorf("unexpected log entry: %+v", entries[0])
	}
}

type mockGuardClient struct {
	claimTokenFunc      func(ctx context.Context, jti string) (string, error)
	registerPendingFunc func(ctx context.Context, jti, jwt string) error
}

func (m *mockGuardClient) ClaimToken(ctx context.Context, jti string) (string, error) {
	if m.claimTokenFunc != nil {
		return m.claimTokenFunc(ctx, jti)
	}
	return "", nil
}
func (m *mockGuardClient) RegisterPending(ctx context.Context, jti, jwt string) error {
	if m.registerPendingFunc != nil {
		return m.registerPendingFunc(ctx, jti, jwt)
	}
	return nil
}

type mockTokenStore struct {
	tokens  []shared.EscalationToken
	addFunc func(ctx context.Context, raw string) (shared.EscalationToken, error)
}

func (m *mockTokenStore) All(_ context.Context) []shared.EscalationToken {
	return m.tokens
}
func (m *mockTokenStore) Add(ctx context.Context, raw string) (shared.EscalationToken, error) {
	if m.addFunc != nil {
		return m.addFunc(ctx, raw)
	}
	return shared.EscalationToken{}, nil
}
func (m *mockTokenStore) Delete(_ context.Context, _ string) error {
	return nil
}

// ---- EscalationManager tests ------------------------------------------------

func TestCollectEscalationTokens_Claim(t *testing.T) {
	pending := NewInMemoryPendingStore()
	pending.Store(context.Background(), "srv/tool", pendingEscalation{
		ServerName: "srv",
		ToolName:   "tool",
		JTI:        "jti-123",
		ExpiresAt:  time.Now().Add(time.Hour),
	})

	guard := &mockGuardClient{
		claimTokenFunc: func(ctx context.Context, jti string) (string, error) {
			if jti == "jti-123" {
				return "raw-token", nil
			}
			return "", nil
		},
	}

	tokens := &mockTokenStore{}
	tokens.tokens = []shared.EscalationToken{}
	tokens.addFunc = func(ctx context.Context, raw string) (shared.EscalationToken, error) {
		tok := shared.EscalationToken{TokenID: "tok-id"}
		tokens.tokens = append(tokens.tokens, tok)
		return tok, nil
	}

	mgr := NewEscalationManager(guard, pending, tokens, EscalationConfig{}, NewSingleTenantProvider(nil, ""), nil, "")
	res := mgr.CollectTokens(context.Background(), "srv", "tool")
	if len(res) != 1 || res[0].TokenID != "tok-id" {
		t.Errorf("expected 1 token 'tok-id', got %v", res)
	}

	if _, ok := pending.Get(context.Background(), "srv/tool"); ok {
		t.Error("pending escalation should have been deleted after claim")
	}
}

func TestMaybeStorePendingEscalation_Proactive(t *testing.T) {
	guard := &mockGuardClient{
		registerPendingFunc: func(ctx context.Context, jti, jwt string) error {
			if jti != "jti-proactive" {
				return errors.New("wrong jti")
			}
			return nil
		},
	}
	pending := NewInMemoryPendingStore()

	mgr := NewEscalationManager(guard, pending, &mockTokenStore{}, EscalationConfig{}, NewSingleTenantProvider(nil, ""), nil, "")

	err := &shared.EscalationPendingError{
		EscalationJTI: "jti-proactive",
		PendingJWT:    "jwt-data",
	}

	errResult := mgr.StorePending(context.Background(), "srv", "tool", err)
	if errResult != nil {
		t.Fatalf("unexpected error: %v", errResult)
	}

	p, ok := pending.Get(context.Background(), "srv/tool")
	if !ok || p.JTI != "jti-proactive" {
		t.Errorf("pending escalation not stored correctly: %+v", p)
	}
}


// ---- BatchDecisionLogger tests ----------------------------------------------

func TestBatchDecisionLogger_Worker(t *testing.T) {
	received := make(chan []DecisionLogEntry, 1)
	fwd := &mockForwarderWithSendLogs{
		sendLogsFunc: func(ctx context.Context, entries []DecisionLogEntry) error {
			received <- entries
			return nil
		},
	}

	logger := NewBatchDecisionLogger(DecisionLogBatchConfig{
		FlushInterval: 1,
		MaxBatchSize:  2,
	}, fwd)

	ctx, cancel := context.WithCancel(context.Background())
	logger.Start(ctx)

	// 1. Batch size trigger
	logger.Log(DecisionLogEntry{ToolName: "t1"})
	logger.Log(DecisionLogEntry{ToolName: "t2"})

	select {
	case batch := <-received:
		if len(batch) != 2 {
			t.Errorf("expected batch of 2, got %d", len(batch))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for batch flush")
	}

	// 2. Interval trigger
	logger.Log(DecisionLogEntry{ToolName: "t3"})
	select {
	case batch := <-received:
		if len(batch) != 1 {
			t.Errorf("expected batch of 1, got %d", len(batch))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for interval flush")
	}

	// 3. Shutdown flush
	logger.Log(DecisionLogEntry{ToolName: "t4"})
	cancel()
	logger.Wait()

	select {
	case batch := <-received:
		if len(batch) != 1 || batch[0].ToolName != "t4" {
			t.Errorf("expected shutdown flush of 't4', got %v", batch)
		}
	default:
		t.Error("expected shutdown flush")
	}
}


func TestGate_New_Variants(t *testing.T) {
	ctx := context.Background()

	t.Run("multi-tenant", func(t *testing.T) {
		cfg := Config{
			Mode:       "development",
			Tenancy:    "multi",
			Escalation: "disabled",
			Peers: PeersConfig{
				Keep: cfgloader.PeerAuth{Endpoint: "http://keep"},
			},
			Identity: IdentityConfig{Strategy: "os"},
			Server: cfgloader.ServerConfig{
				Endpoints: map[string]cfgloader.EndpointConfig{
					MCPEndpoint: {Listen: "127.0.0.1:0"},
				},
				SessionTTL: 3600,
			},
		}
		g, err := New(ctx, cfg)
		assert.NoError(t, err)
		assert.NotNil(t, g)
		_, ok := g.provider.(*MultiTenantProvider)
		assert.True(t, ok)
	})

	t.Run("multi-tenant-redis", func(t *testing.T) {
		mr := miniredis.RunT(t)
		cfg := Config{
			Mode:       "development",
			Tenancy:    "multi",
			Escalation: "disabled",
			Peers: PeersConfig{
				Keep: cfgloader.PeerAuth{Endpoint: "http://keep"},
			},
			Identity: IdentityConfig{Strategy: "os"},
			Server: cfgloader.ServerConfig{
				Endpoints: map[string]cfgloader.EndpointConfig{
					MCPEndpoint: {Listen: "127.0.0.1:0"},
				},
				SessionTTL: 3600,
			},
			Operations: cfgloader.OperationsConfig{
				Storage: cfgloader.StorageConfig{
					Backend: "redis",
					Config:  map[string]any{"addr": mr.Addr()},
				},
			},
		}
		g, err := New(ctx, cfg)
		assert.NoError(t, err)
		assert.NotNil(t, g)
		assert.NotNil(t, g.sessions)
	})

	t.Run("oidc-login-strategy", func(t *testing.T) {
		cfg := Config{
			Mode:       "development",
			Tenancy:    "single",
			Escalation: "disabled",
			Peers: PeersConfig{
				Keep: cfgloader.PeerAuth{Endpoint: "http://keep"},
			},
			Identity: IdentityConfig{
				Strategy: "oidc-login",
				Config: map[string]any{
					"issuer_url":    "http://idp",
					"redirect_uri":  "http://localhost/callback",
					"client_id":     "id",
					"client_secret": "secret",
				},
			},
			Server: cfgloader.ServerConfig{
				Endpoints: map[string]cfgloader.EndpointConfig{
					ManagementUIEndpoint: {Listen: "127.0.0.1:9090"},
				},
			},
			Responsibility: ResponsibilityConfig{
				Escalation: EscalationConfig{
					TokenStore: filepath.Join(t.TempDir(), "tokens.json"),
				},
			},
		}
		g, err := New(ctx, cfg)
		assert.NoError(t, err)
		assert.NotNil(t, g)
	})

	t.Run("invalid config", func(t *testing.T) {
		cfg := Config{
			Mode:    "development",
			Tenancy: "single",
			// Missing Peers.Keep will fail validation
		}
		g, err := New(ctx, cfg)
		assert.Error(t, err)
		assert.Nil(t, g)
	})
}

func TestGate_HandleLoginTool(t *testing.T) {
	ctx := context.Background()

	t.Run("os strategy", func(t *testing.T) {
		g := &Gate{
			cfg: Config{
				Identity: IdentityConfig{Strategy: "os"},
			},
		}
		msg := g.handleLoginTool(ctx, false)
		assert.Contains(t, msg, "not necessary")
	})

	t.Run("oidc already authenticated", func(t *testing.T) {
		sm := NewStateMachine()
		sm.SetAuthenticated()
		g := &Gate{
			cfg: Config{
				Identity: IdentityConfig{Strategy: "oidc-login"},
			},
			stateMachine: sm,
		}
		msg := g.handleLoginTool(ctx, false)
		assert.Contains(t, msg, "already successfully logged in")
	})

	t.Run("oidc forcing new login", func(t *testing.T) {
		sm := NewStateMachine()
		sm.SetAuthenticated()
		idSource := &mockIdentitySource{}

		loginMgr := NewOIDCLoginManager(OIDCLoginConfig{
			IssuerURL:   "http://idp",
			RedirectURI: "http://localhost",
			ClientID:    "id",
		}, 7777, 600, sm, idSource, nil, nil, nil)

		g := &Gate{
			cfg: Config{
				Identity: IdentityConfig{Strategy: "oidc-login"},
			},
			stateMachine: sm,
			oidcLogin:    loginMgr,
		}
		// It will fail discovery, but we want to see it calls StartLogin.
		msg := g.handleLoginTool(ctx, true)
		assert.Contains(t, msg, "Failed to start login")
	})
}

func TestGate_RegisterTool_Logic(t *testing.T) {
	idSource := &mockIdentitySource{identity: shared.UserIdentity{UserID: "u1"}}
	g := &Gate{
		identity: idSource,
		forwarder: &mockForwarder{
			callToolFunc: func(ctx context.Context, req shared.EnrichedMCPRequest) (*mcp.CallToolResult, error) {
				arg := req.Arguments["foo"].(string)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: arg}}}, nil
			},
		},
		toolServerMap: map[string]string{"t1": "s1"},
		escalations:   &mockTokenStore{},
		escalationMgr: NewEscalationManager(nil, NewInMemoryPendingStore(), &mockTokenStore{}, EscalationConfig{}, NewSingleTenantProvider(nil, ""), idSource, ""),
		logger:        &captureLogger{},
	}

	res, err := g.handleToolCall(context.Background(), "t1", map[string]any{"foo": "bar"})
	assert.NoError(t, err)
	assert.Equal(t, "bar", res.Content[0].(*mcp.TextContent).Text)
}

func TestGate_RefreshKeepTools(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		fwd := &mockForwarder{
			ListToolsFunc: func(ctx context.Context, id shared.UserIdentity, tokens []shared.EscalationToken) ([]shared.AnnotatedTool, error) {
				return []shared.AnnotatedTool{
					{
						Tool: &mcp.Tool{
							Name: "t1",
							InputSchema: struct {
								Type       string   `json:"type"`
								Properties any      `json:"properties,omitempty"`
								Required   []string `json:"required,omitempty"`
							}{
								Type: "object",
							},
						},
						ServerName: "s1",
					},
				}, nil
			},
		}

		g := &Gate{
			forwarder:     fwd,
			identity:      &mockIdentitySource{},
			escalations:   &mockTokenStore{},
			toolServerMap: make(map[string]string),
			// Minimal server to satisfy registerTool
			server: mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1.0"}, nil),
		}

		names, err := g.refreshKeepTools(ctx)
		assert.NoError(t, err)
		assert.ElementsMatch(t, []string{"t1"}, names)
		assert.Equal(t, "s1", g.toolServerMap["t1"])
	})

	t.Run("failure", func(t *testing.T) {
		fwd := &mockForwarder{
			ListToolsFunc: func(ctx context.Context, id shared.UserIdentity, tokens []shared.EscalationToken) ([]shared.AnnotatedTool, error) {
				return nil, errors.New("keep down")
			},
		}
		sm := NewStateMachine()
		g := &Gate{
			cfg:          Config{Identity: IdentityConfig{Strategy: "os"}},
			forwarder:    fwd,
			identity:     &mockIdentitySource{},
			escalations:  &mockTokenStore{},
			stateMachine: sm,
		}

		names, err := g.refreshKeepTools(ctx)
		assert.Error(t, err)
		assert.Nil(t, names)
		assert.Equal(t, StateSystemError, sm.State())
	})
}

func TestGate_Run(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := Config{
		Mode:       "development",
		Tenancy:    "single",
		Escalation: "disabled",
		Server: cfgloader.ServerConfig{
			Endpoints: map[string]cfgloader.EndpointConfig{
				MCPEndpoint:          {Listen: "127.0.0.1:0"},
				ManagementUIEndpoint: {Listen: "127.0.0.1:0"},
			},
		},
		Peers: PeersConfig{
			Keep: cfgloader.PeerAuth{Endpoint: "http://keep"},
		},
		Identity: IdentityConfig{Strategy: "os"},
		Operations: cfgloader.OperationsConfig{
			Storage: cfgloader.StorageConfig{
				Backend: "redis",
				Config:  map[string]any{"addr": mr.Addr()},
			},
		},
		Responsibility: ResponsibilityConfig{
			Escalation: EscalationConfig{
				TokenStore: filepath.Join(t.TempDir(), "tokens.json"),
			},
		},
	}

	g, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Run should return when context is cancelled or server stops.
	err = g.Run(ctx)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, net.ErrClosed) {
		t.Errorf("Run returned unexpected error: %v", err)
	}
}
