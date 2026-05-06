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
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/paclabsnet/PortcullisMCP/internal/gate/localfs"
	"github.com/paclabsnet/PortcullisMCP/internal/shared"
	"github.com/paclabsnet/PortcullisMCP/internal/telemetry"
	"github.com/paclabsnet/PortcullisMCP/internal/version"
)

type gateCtxKey string

const (
	sessionIDKey     gateCtxKey = "sessionID"
	userIDKey        gateCtxKey = "userID"
	identityKey      gateCtxKey = "identity"
	clientHeadersKey gateCtxKey = "clientHeaders"
)

// SessionIDFromContext returns the session ID stored in ctx, or ("", false) if absent.
func SessionIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(sessionIDKey).(string)
	return v, ok
}

// withSessionID returns a new context carrying the given session ID.
func withSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sessionIDKey, sessionID)
}

// withClientHeaders returns a new context carrying the extracted client headers.
func withClientHeaders(ctx context.Context, headers map[string][]string) context.Context {
	return context.WithValue(ctx, clientHeadersKey, headers)
}

// clientHeadersFromContext returns the client headers stored in ctx, or nil if absent.
func clientHeadersFromContext(ctx context.Context) map[string][]string {
	v, _ := ctx.Value(clientHeadersKey).(map[string][]string)
	return v
}

// DecisionLogEntry is a fast-path decision log entry sent to Keep.
type DecisionLogEntry struct {
	Timestamp time.Time      `json:"timestamp"`
	SessionID string         `json:"session_id"`
	TraceID   string         `json:"trace_id"`
	UserID    string         `json:"user_id"`
	ToolName  string         `json:"tool_name"`
	Decision  string         `json:"decision"` // "allow" | "deny"
	Reason    string         `json:"reason"`
	Source    string         `json:"source"` // always "gate-fastpath"
	Arguments map[string]any `json:"arguments,omitempty"`
}

// pendingEscalation tracks an in-flight escalation request.
type pendingEscalation struct {
	ServerName string
	ToolName   string
	JTI        string
	ExpiresAt  time.Time
}

// KeepForwarder defines the interface for communicating with Portcullis Keep.
type KeepForwarder interface {
	CallTool(ctx context.Context, req shared.EnrichedMCPRequest) (*mcp.CallToolResult, error)
	Authorize(ctx context.Context, req shared.EnrichedMCPRequest) error
	ListTools(ctx context.Context, identity shared.UserIdentity, escalationTokens []shared.EscalationToken) ([]shared.AnnotatedTool, error)
	SendLogs(ctx context.Context, entries []DecisionLogEntry) error
	GetStaticPolicy(ctx context.Context, resource string) (json.RawMessage, error)
}

// GuardSource defines the interface for communicating with Portcullis Guard.
type GuardSource interface {
	ListUnclaimedTokens(ctx context.Context, userID string) ([]unclaimedTokenInfo, error)
	RegisterPending(ctx context.Context, jti, jwt string) error
	ClaimToken(ctx context.Context, jti string) (string, error)
}

// Gate is the portcullis-gate MCP proxy server.
type Gate struct {
	cfg             Config
	sessions        SessionStore           // handles session state
	escalations     EscalationTokenStore   // handles escalation JWTs
	pending         PendingEscalationStore // handles in-flight requests
	identity        IdentitySource         // handles user info resolution
	forwarder       KeepForwarder
	guardClient     GuardSource // nil if Guard endpoint not configured
	server          *mcp.Server
	localFS         *mcp.ClientSession // in-process filesystem backend
	localFSServer   *localfs.Server    // nil when localFS is disabled
	localFSPolicyMu sync.RWMutex
	localFSPolicy   *localFSPolicy // nil = degraded (no valid policy yet)
	sessionID       string
	toolServerMap   map[string]string // tool name → backend server name
	localFSTools    map[string]bool   // tools served by local filesystem
	logChan         chan DecisionLogEntry
	logDone         chan struct{}
	logWg           sync.WaitGroup
	provider        TenancyProvider

	stateMachine *StateMachine
	oidcLogin    *OIDCLoginManager
}

// New creates a Gate from the given config.
func New(ctx context.Context, cfg Config) (*Gate, error) {
	sm := NewStateMachine()

	identityCache, err := NewIdentityCache(ctx, cfg.Identity)
	if err != nil {
		return nil, fmt.Errorf("resolve identity: %w", err)
	}

	storePath := cfg.Responsibility.Escalation.TokenStore
	if storePath == "" {
		storePath = "~/.portcullis/tokens.json"
	}
	// For tenancy: single, EscalationTokenStore must remain file-backed so that
	// approved tokens survive server restarts.
	tokenStore, err := NewTokenStore(ctx, storePath)
	if err != nil {
		return nil, fmt.Errorf("open token store: %w", err)
	}

	fwd, err := NewForwarder(cfg.Peers.Keep)
	if err != nil {
		return nil, fmt.Errorf("create forwarder: %w", err)
	}

	// Initialize tenancy provider. Sessions are wired in after sessionStore is set up below.
	mcpEpCfg := cfg.Server.Endpoints[MCPEndpoint]
	var provider TenancyProvider
	if cfg.Tenancy == "multi" {
		provider = NewMultiTenantProvider(mcpEpCfg.Auth.Credentials.Header, nil, nil)
	} else {
		provider = NewSingleTenantProvider(identityCache, mcpEpCfg.Auth.Credentials.Header)
	}

	// Start the in-process local filesystem server if enabled.
	// Hard-blocked in multi-tenant mode regardless of the Enabled flag or workspace dirs,
	// so that a misconfigured config file cannot violate tenant isolation at runtime.
	// When rules.source is "keep", the server starts in degraded (deny-all) state and
	// is activated by the policy refresh loop in Run().
	var localFSSession *mcp.ClientSession
	var localFSServer *localfs.Server
	var initDirs []string // expanded workspace dirs for source:"local"; nil for source:"keep"
	if provider.Capabilities().AllowLocalFS && cfg.Responsibility.Tools.LocalFS.Enabled {
		localFSRules := cfg.Responsibility.Tools.LocalFS.Rules
		if localFSRules.Source == "local" {
			rawDirs := cfg.Responsibility.Tools.LocalFS.Workspace.EffectiveDirs()
			if len(rawDirs) > 0 {
				initDirs = make([]string, 0, len(rawDirs))
				for _, d := range rawDirs {
					exp, err := expandHome(d)
					if err != nil {
						return nil, fmt.Errorf("expand sandbox dir %q: %w", d, err)
					}
					initDirs = append(initDirs, exp)
				}
			}
		}
		// For source:"keep", initDirs is nil — server starts degraded.
		// For source:"local" with no dirs configured, skip starting localfs entirely.
		if localFSRules.Source == "keep" || len(initDirs) > 0 {
			var err error
			localFSServer, localFSSession, err = localfs.Connect(ctx, initDirs)
			if err != nil {
				return nil, fmt.Errorf("start local filesystem server: %w", err)
			}
		}
	}

	// For source:"local", seed the runtime policy from config immediately.
	// For source:"keep", policy starts nil (degraded) until the first fetch succeeds.
	var initialLocalFSPolicy *localFSPolicy
	if cfg.Responsibility.Tools.LocalFS.Rules.Source == "local" && localFSSession != nil {
		rawForbidden := cfg.Responsibility.Tools.LocalFS.Forbidden.Directories
		expandedForbidden := make([]string, 0, len(rawForbidden))
		for _, d := range rawForbidden {
			exp, err := expandHome(d)
			if err != nil {
				return nil, fmt.Errorf("expand forbidden dir %q: %w", d, err)
			}
			expandedForbidden = append(expandedForbidden, exp)
		}
		initialLocalFSPolicy = &localFSPolicy{
			Workspace: SandboxConfig{Directories: initDirs},
			Forbidden: ForbiddenConfig{Directories: expandedForbidden},
			Strategy:  cfg.Responsibility.Tools.LocalFS.Strategy,
		}
	}

	var guardClient GuardSource
	if cfg.Peers.Guard.resolvedAPIEndpoint() != "" {
		gc, err := NewGuardClient(cfg.Peers.Guard)
		if err != nil {
			return nil, fmt.Errorf("init guard client: %w", err)
		}
		guardClient = gc
	}

	// Initialize session store. In multi-tenant mode, Redis is preferred for
	// shared state across instances; memory is the fallback for single-tenant
	// and development use.
	var sessionStore SessionStore
	if cfg.Operations.Storage.Backend == "redis" {
		sc := cfg.Operations.Storage.Config
		addr, _ := sc["addr"].(string)
		password, _ := sc["password"].(string)
		db, _ := sc["db"].(int)
		keyPrefix, _ := sc["key_prefix"].(string)
		rs, err := NewRedisSessionStore(ctx, RedisConfig{
			Addr:      addr,
			Password:  password,
			DB:        db,
			KeyPrefix: keyPrefix,
		}, cfg.Server.SessionTTL)
		if err != nil {
			return nil, err
		}
		sessionStore = rs
	} else {
		sessionStore = NewMemorySessionStore()
	}
	if mtp, ok := provider.(*MultiTenantProvider); ok {
		mtp.sessions = sessionStore
	}

	if _, err := cfg.Validate(nil); err != nil {
		return nil, err
	}

	var oidcLoginMgr *OIDCLoginManager
	if cfg.Identity.Strategy == "oidc-login" {
		mgmtEndpoint := cfg.Server.Endpoints[ManagementUIEndpoint]
		mgmtPort := DefaultManagementAPIPort
		if mgmtEndpoint.Listen != "" {
			_, portStr, err := net.SplitHostPort(mgmtEndpoint.Listen)
			if err == nil {
				fmt.Sscanf(portStr, "%d", &mgmtPort)
			}
		}
		oidcLoginMgr = nil // placeholder; we need the Gate struct first
	} else {
		sm.SetAuthenticated()
	}

	g := &Gate{
		cfg:           cfg,
		sessions:      sessionStore,
		identity:      identityCache,
		escalations:   tokenStore,
		pending:       NewInMemoryPendingStore(),
		forwarder:     fwd,
		guardClient:   guardClient,
		localFS:       localFSSession,
		localFSServer: localFSServer,
		localFSPolicy: initialLocalFSPolicy,
		sessionID:     uuid.New().String(),
		toolServerMap: make(map[string]string),
		localFSTools:  make(map[string]bool),
		logChan:       make(chan DecisionLogEntry, 1000),
		logDone:       make(chan struct{}),
		stateMachine:  sm,
		provider:      provider,
	}
	if mtp, ok := provider.(*MultiTenantProvider); ok {
		mtp.logChan = g.logChan
	}

	if cfg.Identity.Strategy == "oidc-login" {
		mgmtEndpoint := cfg.Server.Endpoints[ManagementUIEndpoint]
		mgmtPort := DefaultManagementAPIPort
		if mgmtEndpoint.Listen != "" {
			_, portStr, err := net.SplitHostPort(mgmtEndpoint.Listen)
			if err == nil {
				fmt.Sscanf(portStr, "%d", &mgmtPort)
			}
		}
		oidcLoginMgr = NewOIDCLoginManager(
			cfg.Identity.OIDCLogin,
			mgmtPort,
			cfg.Identity.LoginCallbackTimeoutSecs,
			sm,
			g.identity, // OIDCLoginManager calls SetToken directly
			func(_ string) {
				// Side effect: refresh Keep tool list after successful login/refresh.
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					g.refreshKeepTools(ctx)
				}()
			},
			func() {
				slog.Info("oidc-login: session expired; agent must log in again")
			},
			func(err error) {
				slog.Error("oidc-login: refresh failed", "error", err)
			},
		)
		g.oidcLogin = oidcLoginMgr
	}

	g.logWg.Add(1)
	go g.logWorker()

	g.server = mcp.NewServer(&mcp.Implementation{
		Name:    shared.ServiceGate,
		Version: version.Version,
	}, nil)

	// Native tools are single-tenant only. In multi-tenant mode health and
	// readiness are served via /healthz and /readyz on the HTTP transport.
	if provider.Capabilities().AllowNativeTools {
		mcp.AddTool(g.server,
			&mcp.Tool{
				Name:        "portcullis_status",
				Description: "Returns the current operational status of Portcullis Gate, Keep, and Guard.",
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
				msg, isErr := g.buildStatusReport(ctx)
				return &mcp.CallToolResult{
					IsError: isErr,
					Content: []mcp.Content{&mcp.TextContent{Text: msg}},
				}, nil, nil
			},
		)

		mcp.AddTool(g.server,
			&mcp.Tool{
				Name:        "portcullis_login",
				Description: "Starts or checks the Portcullis login process.",
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, in any) (*mcp.CallToolResult, any, error) {
				force := false
				if inMap, ok := in.(map[string]any); ok {
					if forceVal, ok := inMap["force"].(bool); ok {
						force = forceVal
					}
				}
				msg := g.handleLoginTool(ctx, force)
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: msg}},
				}, nil, nil
			},
		)

		mcp.AddTool(g.server,
			&mcp.Tool{
				Name:        "portcullis_refresh",
				Description: "Refreshes the list of available tools from Keep and returns the updated tool list. Use this after backend services are added, removed, or restarted.",
			},
			func(ctx context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
				names, err := g.refreshKeepTools(ctx)
				if err != nil {
					return &mcp.CallToolResult{
						IsError: true,
						Content: []mcp.Content{&mcp.TextContent{Text: "Failed to refresh tools from Keep: " + err.Error()}},
					}, nil, nil
				}
				msg := fmt.Sprintf("Tool list refreshed successfully. %d tools available from Keep:\n- %s",
					len(names), strings.Join(names, "\n- "))
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: msg}},
				}, nil, nil
			},
		)
	}

	// Double-guard: skip registration even if localFSSession is somehow non-nil
	// in multi-tenant mode (defence-in-depth against future refactors).
	if localFSSession != nil && provider.Capabilities().AllowLocalFS {
		localTools, err := localFSSession.ListTools(ctx, &mcp.ListToolsParams{})
		if err != nil {
			return nil, fmt.Errorf("list local filesystem tools: %w", err)
		}
		for _, tool := range localTools.Tools {
			g.localFSTools[tool.Name] = true
			g.registerTool(tool)
		}
		slog.Info("registered local filesystem tools", "count", len(localTools.Tools))
	}

	g.refreshKeepTools(ctx)

	return g, nil
}

func (g *Gate) refreshKeepTools(ctx context.Context) ([]string, error) {
	keepTools, err := g.forwarder.ListTools(ctx, g.identity.Get(ctx), g.escalations.All())
	if err != nil {
		slog.Warn("fetch tool list from keep failed", "error", err)
		if g.cfg.Identity.Strategy != "oidc-login" {
			g.stateMachine.SetSystemError(SubstateInvalid, "Keep is unreachable — tool list may be incomplete", err.Error())
		}
		return nil, err
	}

	names := make([]string, 0, len(keepTools))
	for _, at := range keepTools {
		g.toolServerMap[at.Tool.Name] = at.ServerName
		g.registerTool(at.Tool)
		names = append(names, at.Tool.Name)
	}
	slog.Info("registered keep tools", "count", len(keepTools))
	return names, nil
}

func (g *Gate) handleLoginTool(ctx context.Context, force bool) string {
	switch g.cfg.Identity.Strategy {
	case "os", "oidc-file":
		return "Login is not necessary."
	case "oidc-login":
		if !force && g.stateMachine.State() == StateAuthenticated {
			return "You are already successfully logged in. Use 'force: true' to get a new login URL."
		}
		if g.oidcLogin == nil {
			return "Login manager is not configured."
		}
		if force {
			slog.Info("forcing new login URL", "source", "portcullis_login force=true")
		}
		loginURL, err := g.oidcLogin.StartLogin(ctx)
		if err != nil {
			return "Failed to start login: " + err.Error()
		}
		mgmtEndpoint := g.cfg.Server.Endpoints[ManagementUIEndpoint]
		mgmtPort := DefaultManagementAPIPort
		if mgmtEndpoint.Listen != "" {
			_, portStr, err := net.SplitHostPort(mgmtEndpoint.Listen)
			if err == nil {
				fmt.Sscanf(portStr, "%d", &mgmtPort)
			}
		}
		shortURL := fmt.Sprintf("http://localhost:%d/auth/login", mgmtPort)
		return fmt.Sprintf(
			"Please log in to Portcullis by clicking this link: [Log in to Portcullis](%s)\n\n"+
				"DISPLAY INSTRUCTIONS: Always render the login link above as a clickable hyperlink. "+
				"Do not show the full direct URL unless the user specifically asks for it. "+
				"If asked, the direct login URL is: %s",
			shortURL, loginURL,
		)
	}
	return "Login is not necessary."
}

func (g *Gate) Run(ctx context.Context) error {
	// Management server and guard polling are single-tenant concerns.
	// Multi-tenant mode forbids both by config validation.
	if g.provider.Capabilities().AllowManagementUI {
		mgmtEndpoint := g.cfg.Server.Endpoints[ManagementUIEndpoint]
		// ManagementServer requires the concrete *IdentityCache (for Info/UpdateToken).
		identityCache, ok := g.identity.(*IdentityCache)
		if !ok {
			return fmt.Errorf("identity source is not an *IdentityCache in single-tenant mode")
		}
		tokenStore, ok := g.escalations.(*TokenStore)
		if !ok {
			return fmt.Errorf("escalation store is not a *TokenStore in single-tenant mode")
		}
		mgmt, err := NewManagementServer(tokenStore, identityCache, mgmtEndpoint, g.cfg.Responsibility.AgentInteraction, g.oidcLogin, g.cfg.Identity.LoginCallbackPageFile)
		if err != nil {
			return fmt.Errorf("init management api: %w", err)
		}
		if err := mgmt.Start(ctx); err != nil {
			return fmt.Errorf("start management api: %w", err)
		}

		if g.guardClient != nil {
			interval := 60 * time.Second
			if g.cfg.Responsibility.Escalation.PollInterval > 0 {
				interval = time.Duration(g.cfg.Responsibility.Escalation.PollInterval) * time.Second
			}
			slog.Info("guard poll worker starting", "endpoint", g.cfg.Peers.Guard.resolvedAPIEndpoint(), "interval", interval)
			go func() {
				g.claimAllUnclaimedTokens(ctx)
				g.pollGuardWorker(ctx)
			}()
		} else {
			slog.Warn("guard endpoint not configured; escalation tokens must be added manually")
		}
	}

	// When localfs policy source is "keep", perform an initial async fetch and
	// start the background refresh loop. The server starts fail-closed: localfs
	// tools are denied until the first successful fetch.
	if g.localFSServer != nil && g.cfg.Responsibility.Tools.LocalFS.Rules.Source == "keep" {
		go func() {
			if err := g.fetchAndApplyLocalFSPolicy(ctx); err != nil {
				slog.Warn("gate: initial localfs policy fetch failed — localfs tool is degraded", "error", err)
			}
		}()
		g.startLocalFSPolicyRefresh(ctx)
	}

	go func() {
		<-ctx.Done()
		close(g.logDone)
		g.logWg.Wait()
	}()

	// HTTP transport if an MCP endpoint is configured; otherwise fall back to stdio.
	mcpEp, hasHTTP := g.cfg.Server.Endpoints[MCPEndpoint]
	if hasHTTP && mcpEp.Listen != "" {
		var sdkOpts *mcp.StreamableHTTPOptions
		if redisStore, ok := g.sessions.(*RedisSessionStore); ok {
			sdkOpts = &mcp.StreamableHTTPOptions{EventStore: redisStore}
		}
		httpHandler := NewMCPHTTPHandler(g.server, sdkOpts, g.cfg, g.provider)

		httpSrv := &http.Server{
			Addr:    mcpEp.Listen,
			Handler: httpHandler,
		}
		go func() {
			<-ctx.Done()
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = httpSrv.Shutdown(shutCtx)
		}()

		slog.Info("gate MCP HTTP transport starting", "addr", mcpEp.Listen, "tenancy", g.cfg.Tenancy)
		if mcpEp.TLS.Cert != "" && mcpEp.TLS.Key != "" {
			if err := httpSrv.ListenAndServeTLS(mcpEp.TLS.Cert, mcpEp.TLS.Key); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		}
		if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}

	return g.server.Run(ctx, &mcp.StdioTransport{})
}

func (g *Gate) registerTool(tool *mcp.Tool) {
	g.server.AddTool(tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args map[string]any
		if req.Params.Arguments != nil {
			data, err := json.Marshal(req.Params.Arguments)
			if err != nil {
				return nil, fmt.Errorf("marshal tool arguments: %w", err)
			}
			if err := json.Unmarshal(data, &args); err != nil {
				return nil, fmt.Errorf("unmarshal tool arguments: %w", err)
			}
		}
		return g.handleToolCall(ctx, req.Params.Name, args)
	})
}

func (g *Gate) handleToolCall(ctx context.Context, toolName string, args map[string]any) (*mcp.CallToolResult, error) {
	// Ensure a sessionID is in context. In single-tenant mode the Gate has one
	// global session; in multi-tenant mode the HTTP middleware injects it first.
	if _, hasSession := SessionIDFromContext(ctx); !hasSession {
		ctx = withSessionID(ctx, g.sessionID)
	}
	sessionID, _ := SessionIDFromContext(ctx)

	ctx, span := otel.Tracer(shared.ServiceGate).Start(ctx, "gate.tool_call")
	defer span.End()
	span.SetAttributes(
		attribute.String("tool.name", toolName),
		attribute.String("session.id", sessionID),
	)

	if g.cfg.Identity.Strategy == "oidc-login" && toolName != "portcullis_status" && toolName != "portcullis_login" {
		state := g.stateMachine.State()
		switch state {
		case StateUnauthenticated:
			loginMsg := g.handleLoginTool(ctx, false)
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: "Authentication required. " + loginMsg}},
			}, nil
		case StateAuthenticating:
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: "Please complete the login process. Use the `portcullis_login` tool to start over."}},
			}, nil
		case StateSystemError:
			summary, detail := g.stateMachine.SystemError()
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Portcullis Gate is having trouble: %s\n\nUse `portcullis_status` tool for more details, or use `portcullis_login` to reset the system and log in again.\n\nDetail: %s", summary, detail)}},
			}, nil
		}
	}

	traceID := telemetry.TraceIDFromContext(ctx)
	if traceID == "" {
		traceID = uuid.New().String()
	}

	fpResult, err := g.FastPath(ctx, toolName, args)
	if err != nil {
		return nil, err
	}

	paths := extractPaths(args)
	path := ""
	if len(paths) > 0 {
		path = paths[0]
	}

	switch fpResult {
	case FastPathAllow:
		span.SetAttributes(attribute.String("pdp.decision", "allow"), attribute.String("pdp.source", "fastpath"))
		slog.InfoContext(ctx, "fast-path allow", "tool", toolName, "path", path, "trace_id", traceID)

		select {
		case g.logChan <- DecisionLogEntry{
			Timestamp: time.Now().UTC(),
			SessionID: sessionID,
			TraceID:   traceID,
			UserID:    g.identity.Get(ctx).UserID,
			ToolName:  toolName,
			Decision:  "allow",
			Reason:    "sandbox",
			Source:    "gate-fastpath",
			Arguments: args,
		}:
		default:
		}

		if g.localFS == nil {
			return nil, fmt.Errorf("local filesystem server not configured")
		}
		return g.localFS.CallTool(ctx, &mcp.CallToolParams{
			Name:      toolName,
			Arguments: args,
		})

	case FastPathDeny:
		span.SetAttributes(attribute.String("pdp.decision", "deny"), attribute.String("pdp.source", "fastpath"))
		span.SetStatus(codes.Error, "fast-path deny")
		slog.InfoContext(ctx, "fast-path deny", "tool", toolName, "path", path, "trace_id", traceID)

		select {
		case g.logChan <- DecisionLogEntry{
			Timestamp: time.Now().UTC(),
			SessionID: sessionID,
			TraceID:   traceID,
			UserID:    g.identity.Get(ctx).UserID,
			ToolName:  toolName,
			Decision:  "deny",
			Reason:    "protected path",
			Source:    "gate-fastpath",
			Arguments: args,
		}:
		default:
		}

		return nil, shared.ErrDenied
	}

	currentIdentity := g.identity.Get(ctx)

	if g.localFSTools[toolName] {
		enriched := shared.EnrichedMCPRequest{
			APIVersion:       shared.APIVersion,
			ServerName:       shared.LocalFSServerName,
			ToolName:         toolName,
			Arguments:        args,
			UserIdentity:     currentIdentity,
			EscalationTokens: g.collectEscalationTokens(ctx, shared.LocalFSServerName, toolName),
			SessionID:        sessionID,
			TraceID:          traceID,
		}
		if err := g.forwarder.Authorize(ctx, enriched); err != nil {
			if storeErr := g.maybeStorePendingEscalation(ctx, shared.LocalFSServerName, toolName, err); storeErr != nil {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: storeErr.Error()}}}, nil
			}
			return g.policyErrToResult(ctx, err, toolName, traceID)
		}
		if g.localFS == nil {
			return nil, fmt.Errorf("local filesystem server not configured")
		}
		return g.localFS.CallTool(ctx, &mcp.CallToolParams{
			Name:      toolName,
			Arguments: args,
		})
	}

	serverName, ok := g.toolServerMap[toolName]
	if !ok {
		slog.Warn("no server mapping for tool, routing may fail", "tool", toolName)
		serverName = "unknown"
	}
	enriched := shared.EnrichedMCPRequest{
		APIVersion:       shared.APIVersion,
		ServerName:       serverName,
		ToolName:         toolName,
		Arguments:        args,
		UserIdentity:     currentIdentity,
		EscalationTokens: g.collectEscalationTokens(ctx, serverName, toolName),
		SessionID:        sessionID,
		TraceID:          traceID,
		ClientHeaders:    clientHeadersFromContext(ctx),
	}
	result, err := g.forwarder.CallTool(ctx, enriched)
	if err != nil {
		if storeErr := g.maybeStorePendingEscalation(ctx, serverName, toolName, err); storeErr != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: storeErr.Error()}}}, nil
		}
		return g.policyErrToResult(ctx, err, toolName, traceID)
	}
	if result != nil && result.IsError {
		result = g.enrichBackendAuthChallenge(result, serverName, toolName)
	}
	return result, err
}

func (g *Gate) collectEscalationTokens(ctx context.Context, serverName, toolName string) []shared.EscalationToken {
	tokens := g.escalations.All()

	if g.guardClient == nil {
		return tokens
	}

	key := serverName + "/" + toolName
	pending, hasPending := g.pending.Get(key)

	if !hasPending {
		return tokens
	}
	if pending.ExpiresAt.Before(time.Now()) {
		g.pending.Delete(key)
		return tokens
	}

	claimCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	raw, err := g.guardClient.ClaimToken(claimCtx, pending.JTI)
	if err != nil {
		slog.Warn("guard claim token failed", "jti", pending.JTI, "error", err)
		return tokens
	}
	if raw == "" {
		return tokens
	}

	tok, err := g.escalations.Add(ctx, raw)
	if err != nil {
		slog.Warn("store claimed escalation token failed", "jti", pending.JTI, "error", err)
		return tokens
	}

	slog.Info("claimed escalation token from guard",
		"jti", pending.JTI, "token_id", tok.TokenID,
		"server", serverName, "tool", toolName)

	g.pending.Delete(key)

	return g.escalations.All()
}

func (g *Gate) maybeStorePendingEscalation(ctx context.Context, serverName, toolName string, err error) error {
	if !g.provider.Capabilities().AllowHumanInLoop {
		return nil // block storage in PendingEscalationStore in multi-tenant mode
	}

	var escalationErr *shared.EscalationPendingError
	if !errors.As(err, &escalationErr) {
		return nil
	}
	if escalationErr.EscalationJTI == "" {
		return nil
	}
	if g.guardClient == nil {
		return nil
	}

	if g.isProactive() {
		pushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if regErr := g.guardClient.RegisterPending(pushCtx, escalationErr.EscalationJTI, escalationErr.PendingJWT); regErr != nil {
			slog.Error("proactive: failed to register pending escalation with Guard",
				"jti", escalationErr.EscalationJTI, "error", regErr)
			return fmt.Errorf("escalation required but Guard is currently unreachable")
		}
		slog.Info("proactive: registered pending escalation with Guard",
			"jti", escalationErr.EscalationJTI, "server", serverName, "tool", toolName)
	}

	key := serverName + "/" + toolName
	expiry := time.Now().Add(24 * time.Hour)

	g.pending.Store(key, pendingEscalation{
		ServerName: serverName,
		ToolName:   toolName,
		JTI:        escalationErr.EscalationJTI,
		ExpiresAt:  expiry,
	})

	slog.Info("stored pending escalation",
		"server", serverName, "tool", toolName, "jti", escalationErr.EscalationJTI)
	return nil
}

func (g *Gate) isProactive() bool {
	return g.cfg.Responsibility.Escalation.Strategy == "proactive"
}

const defaultRequireApprovalInstructions = "Escalation required: {reason}\n\nPresent this complete URL to the user so they can click it to approve the request. Do not truncate or shorten the URL:\n{url}\n\nTrace ID: {trace_id}"
const defaultDenyInstructions = "Access denied: {reason}\n\nIf you believe this is incorrect, contact your security team and reference trace ID: {trace_id}"

func (g *Gate) buildDenyMessage(reason, traceID string) string {
	instructions := g.cfg.Responsibility.AgentInteraction.Instructions.Deny
	if instructions == "" {
		instructions = defaultDenyInstructions
	}
	msg := strings.ReplaceAll(instructions, "{reason}", reason)
	msg = strings.ReplaceAll(msg, "{trace_id}", traceID)
	return msg
}

func (g *Gate) buildEscalationMessage(e *shared.EscalationPendingError, traceID string) string {
	guardEndpoint := g.cfg.Peers.Guard.Endpoints.ApprovalUI

	var approvalURL string
	if guardEndpoint != "" {
		if g.isProactive() && e.EscalationJTI != "" {
			approvalURL = guardEndpoint + "/approve?jti=" + url.QueryEscape(e.EscalationJTI)
		} else if e.PendingJWT != "" {
			approvalURL = guardEndpoint + "/approve?token=" + url.QueryEscape(e.PendingJWT)
		}
	}
	if approvalURL == "" && e.Reference != "" {
		approvalURL = e.Reference
	}

	if approvalURL == "" {
		slog.Warn("escalation required but no approval URL available", "reason", e.Reason)
		msg := "Escalation required: " + e.Reason
		if msg != "" {
			msg += "\n\nNo approval URL is available. The system may be misconfigured. Please contact your administrator."
		}
		return msg
	}

	instructions := g.cfg.Responsibility.AgentInteraction.Instructions.RequireApproval
	if instructions == "" {
		instructions = defaultRequireApprovalInstructions
	}

	msg := strings.ReplaceAll(instructions, "{reason}", e.Reason)
	msg = strings.ReplaceAll(msg, "{url}", approvalURL)
	msg = strings.ReplaceAll(msg, "{trace_id}", traceID)
	return msg
}

func (g *Gate) pollGuardWorker(ctx context.Context) {
	interval := 60 * time.Second
	if g.cfg.Responsibility.Escalation.PollInterval > 0 {
		interval = time.Duration(g.cfg.Responsibility.Escalation.PollInterval) * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.claimAllUnclaimedTokens(ctx)
		}
	}
}

func (g *Gate) claimAllUnclaimedTokens(ctx context.Context) {
	userID := g.identity.Get(ctx).UserID
	if userID == "" {
		return
	}

	listCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	unclaimed, err := g.guardClient.ListUnclaimedTokens(listCtx, userID)
	if err != nil {
		slog.Warn("poll guard unclaimed tokens failed", "error", err)
		return
	}
	slog.Info("polled guard for unclaimed tokens", "user_id", userID, "count", len(unclaimed))
	if len(unclaimed) == 0 {
		return
	}

	for _, entry := range unclaimed {
		claimCtx, claimCancel := context.WithTimeout(ctx, 5*time.Second)
		raw, claimErr := g.guardClient.ClaimToken(claimCtx, entry.JTI)
		claimCancel()

		if claimErr != nil {
			slog.Warn("guard poll claim failed", "jti", entry.JTI, "error", claimErr)
			continue
		}
		if raw == "" {
			continue
		}

		tok, storeErr := g.escalations.Add(ctx, raw)
		if storeErr != nil {
			slog.Warn("store polled token failed", "jti", entry.JTI, "error", storeErr)
			continue
		}

		slog.Info("claimed escalation token via poll", "jti", entry.JTI, "token_id", tok.TokenID)

		g.pending.DeleteByJTI(entry.JTI)
	}
}

// enrichBackendAuthChallenge checks whether result is an error CallToolResult
// whose content contains a WWW-Authenticate header from a backend HTTP response.
// If so, it replaces the raw header dump with a structured, agent-friendly
// message that names the backend, explains the auth challenge, and tells the
// agent what to do. The check is case-insensitive so it works regardless of
// how the header name was canonicalized by the HTTP stack.
func (g *Gate) enrichBackendAuthChallenge(result *mcp.CallToolResult, serverName, toolName string) *mcp.CallToolResult {
	if len(result.Content) == 0 {
		return result
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || text.Text == "" {
		return result
	}
	var wwwAuth string
	for _, line := range strings.Split(text.Text, "\n") {
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:idx]), "www-authenticate") {
			wwwAuth = strings.TrimSpace(line[idx+1:])
			break
		}
	}
	if wwwAuth == "" {
		return result
	}
	msg := fmt.Sprintf(
		"Authentication required to call tool %q on backend %q.\n\n"+
			"The backend issued an authentication challenge:\n"+
			"  WWW-Authenticate: %s\n\n"+
			"Obtain a valid credential for the %q backend and ensure it is "+
			"configured in your Gate identity settings, or contact your administrator.",
		toolName, serverName, wwwAuth, serverName,
	)
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}

func (g *Gate) policyErrToResult(ctx context.Context, err error, toolName, traceID string) (*mcp.CallToolResult, error) {
	var escalationErr *shared.EscalationPendingError
	var denyErr *shared.DenyError
	var identityErr *shared.IdentityVerificationError

	if result, handled := g.provider.MapPolicyError(ctx, err, toolName, traceID, &g.cfg); handled {
		return result, nil
	}

	switch {
	case errors.As(err, &escalationErr):
		effectiveTraceID := escalationErr.TraceID
		if effectiveTraceID == "" {
			effectiveTraceID = traceID
		}
		if g.cfg.Peers.Guard.resolvedAPIEndpoint() == "" {
			slog.Warn("escalation required but Guard is not configured", "tool", toolName, "reason", escalationErr.Reason)
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: g.buildDenyMessage(escalationErr.Reason, effectiveTraceID)}},
			}, nil
		}
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: g.buildEscalationMessage(escalationErr, effectiveTraceID)}},
		}, nil
	case errors.As(err, &denyErr):
		effectiveTraceID := denyErr.TraceID
		if effectiveTraceID == "" {
			effectiveTraceID = traceID
		}
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: g.buildDenyMessage(denyErr.Reason, effectiveTraceID)}},
		}, nil
	case errors.As(err, &identityErr):
		slog.Warn("identity verification failed", "error", identityErr.Reason, "trace_id", traceID)
		if g.cfg.Identity.Strategy == "oidc-login" {
			g.stateMachine.SetUnauthenticated()
			g.identity.Clear()
			loginMsg := g.handleLoginTool(ctx, false)
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: "Your authentication has expired. " + loginMsg}},
			}, nil
		}
		return nil, err
	case errors.Is(err, shared.ErrDenied):
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: g.buildDenyMessage("", traceID)}},
		}, nil
	}
	slog.Error("keep call failed", "error", err, "tool", toolName, "request_id", traceID)
	return nil, err
}

func (g *Gate) logWorker() {
	defer g.logWg.Done()

	flushInterval := 30 * time.Second
	if g.cfg.Responsibility.DecisionLogs.FlushInterval > 0 {
		flushInterval = time.Duration(g.cfg.Responsibility.DecisionLogs.FlushInterval) * time.Second
	}

	maxBatchSize := 100
	if g.cfg.Responsibility.DecisionLogs.MaxBatchSize > 0 {
		maxBatchSize = g.cfg.Responsibility.DecisionLogs.MaxBatchSize
	}

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	var batch []DecisionLogEntry

	for {
		select {
		case <-g.logDone:
			for {
				select {
				case entry := <-g.logChan:
					batch = append(batch, entry)
				default:
					if len(batch) > 0 {
						g.flushLogs(batch)
					}
					return
				}
			}

		case entry := <-g.logChan:
			batch = append(batch, entry)
			if len(batch) >= maxBatchSize {
				g.flushLogs(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				g.flushLogs(batch)
				batch = batch[:0]
			}
		}
	}
}

func (g *Gate) flushLogs(entries []DecisionLogEntry) {
	if len(entries) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := g.forwarder.SendLogs(ctx, entries); err != nil {
		slog.Warn("failed to send decision logs to keep", "error", err, "count", len(entries))
	} else {
		slog.Debug("sent decision logs to keep", "count", len(entries))
	}
}
