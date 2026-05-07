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
	sessions        SessionStore         // handles session state
	escalations     EscalationTokenStore // handles escalation JWTs
	identity        IdentitySource       // handles user info resolution
	forwarder       KeepForwarder
	escalationMgr   EscalationManager  // abstracts Guard interactions and pending escalation state
	logger          DecisionLogger     // async decision log shipping
	server          *mcp.Server
	localFS         *mcp.ClientSession // in-process filesystem backend
	localFSServer   *localfs.Server    // nil when localFS is disabled
	localFSPolicyMu sync.RWMutex
	localFSPolicy   *localFSPolicy // nil = degraded (no valid policy yet)
	sessionID       string
	toolServerMap   map[string]string // tool name → backend server name
	localFSTools    map[string]bool   // tools served by local filesystem
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

	// Build the decision logger before the Gate struct so it can be wired to the
	// MultiTenantProvider (which also emits decision log entries).
	logger := NewBatchDecisionLogger(cfg.Responsibility.DecisionLogs, fwd)
	if mtp, ok := provider.(*MultiTenantProvider); ok {
		mtp.logger = logger
	}

	escalationMgr := NewEscalationManager(
		guardClient,
		NewInMemoryPendingStore(),
		tokenStore,
		cfg.Responsibility.Escalation,
		provider,
		identityCache,
	)

	if cfg.Identity.Strategy != "oidc-login" {
		sm.SetAuthenticated()
	}

	g := &Gate{
		cfg:           cfg,
		sessions:      sessionStore,
		identity:      identityCache,
		escalations:   tokenStore,
		forwarder:     fwd,
		escalationMgr: escalationMgr,
		logger:        logger,
		localFS:       localFSSession,
		localFSServer: localFSServer,
		localFSPolicy: initialLocalFSPolicy,
		sessionID:     uuid.New().String(),
		toolServerMap: make(map[string]string),
		localFSTools:  make(map[string]bool),
		stateMachine:  sm,
		provider:      provider,
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
		oidcLoginMgr := NewOIDCLoginManager(
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

// isProactive reports whether the configured escalation strategy is "proactive".
// Used by buildEscalationMessage to select the correct approval URL format.
func (g *Gate) isProactive() bool {
	return g.cfg.Responsibility.Escalation.Strategy == "proactive"
}

func (g *Gate) Run(ctx context.Context) error {
	// Start the decision log worker. It flushes remaining entries on ctx cancellation.
	g.logger.Start(ctx)

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

		if g.cfg.Peers.Guard.resolvedAPIEndpoint() != "" {
			slog.Info("guard poll worker starting", "endpoint", g.cfg.Peers.Guard.resolvedAPIEndpoint())
			g.escalationMgr.StartPolling(ctx)
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
			// req.Params.Arguments is json.RawMessage — already raw JSON bytes.
			// Unmarshal directly instead of marshaling to bytes first, eliminating
			// one redundant allocation and copy on every tool call.
			if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
				return nil, fmt.Errorf("decode tool arguments: %w", err)
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

		g.logger.Log(DecisionLogEntry{
			Timestamp: time.Now().UTC(),
			SessionID: sessionID,
			TraceID:   traceID,
			UserID:    g.identity.Get(ctx).UserID,
			ToolName:  toolName,
			Decision:  "allow",
			Reason:    "sandbox",
			Source:    "gate-fastpath",
			Arguments: args,
		})

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

		g.logger.Log(DecisionLogEntry{
			Timestamp: time.Now().UTC(),
			SessionID: sessionID,
			TraceID:   traceID,
			UserID:    g.identity.Get(ctx).UserID,
			ToolName:  toolName,
			Decision:  "deny",
			Reason:    "protected path",
			Source:    "gate-fastpath",
			Arguments: args,
		})

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
			EscalationTokens: g.escalationMgr.CollectTokens(ctx, shared.LocalFSServerName, toolName),
			SessionID:        sessionID,
			TraceID:          traceID,
		}
		if err := g.forwarder.Authorize(ctx, enriched); err != nil {
			if storeErr := g.escalationMgr.StorePending(ctx, shared.LocalFSServerName, toolName, err); storeErr != nil {
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
		EscalationTokens: g.escalationMgr.CollectTokens(ctx, serverName, toolName),
		SessionID:        sessionID,
		TraceID:          traceID,
		ClientHeaders:    clientHeadersFromContext(ctx),
	}
	result, err := g.forwarder.CallTool(ctx, enriched)
	if err != nil {
		if storeErr := g.escalationMgr.StorePending(ctx, serverName, toolName, err); storeErr != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: storeErr.Error()}}}, nil
		}
		return g.policyErrToResult(ctx, err, toolName, traceID)
	}
	if result != nil && result.IsError {
		result = g.enrichBackendAuthChallenge(result, serverName, toolName)
	}
	return result, err
}
