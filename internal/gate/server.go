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
)

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

// pendingEscalation tracks an in-flight escalation request that Gate is waiting
// on the user to approve at Guard. Keyed by serverName+"/"+toolName in Gate's
// pendingEscalations map.
type pendingEscalation struct {
	ServerName string
	ToolName   string
	// JTI is the JWT ID of the Keep-signed pending escalation request JWT.
	// Guard will copy this JTI into the issued escalation token so Gate can
	// correlate the approved token back to this pending entry.
	JTI       string
	ExpiresAt time.Time
}

// Gate is the portcullis-gate MCP proxy server.
// It presents itself to the agent as an MCP server, applies the local
// fast-path for filesystem operations, and forwards everything else to Keep.
type Gate struct {
	cfg           Config
	identity      *IdentityCache
	store         *TokenStore
	forwarder     *Forwarder
	guardClient   *GuardClient // nil if Guard endpoint not configured
	server        *mcp.Server
	localFS       *mcp.ClientSession // in-process filesystem backend
	sessionID     string
	toolServerMap map[string]string // tool name → backend server name, populated at startup
	localFSTools  map[string]bool   // tools served by the local filesystem session
	logChan       chan DecisionLogEntry
	logDone       chan struct{}
	logWg         sync.WaitGroup

	// stateMachine tracks authentication state for the oidc-login flow.
	stateMachine *StateMachine

	// oidcLogin manages the interactive OIDC login flow. nil unless source is "oidc-login".
	oidcLogin *OIDCLoginManager

	// pendingEscalations tracks escalation requests awaiting user approval.
	// Key: serverName+"/"+toolName. Protected by pendingMu.
	pendingMu          sync.Mutex
	pendingEscalations map[string]pendingEscalation
}

// New creates a Gate from the given config. Call Run to start serving.
// cfg must already have secrets resolved (use LoadConfig, which calls the
// shared config loader, for file-based startup).
func New(ctx context.Context, cfg Config) (*Gate, error) {
	sm := NewStateMachine()

	identity, err := NewIdentityCache(ctx, cfg.Identity)
	if err != nil {
		return nil, fmt.Errorf("resolve identity: %w", err)
	}

	storePath := cfg.TokenStore
	if storePath == "" {
		storePath = "~/.portcullis/tokens.json"
	}
	store, err := NewTokenStore(ctx, storePath)
	if err != nil {
		return nil, fmt.Errorf("open token store: %w", err)
	}

	fwd, err := NewForwarder(cfg.Keep)
	if err != nil {
		return nil, fmt.Errorf("create forwarder: %w", err)
	}

	// Start the in-process local filesystem server if a sandbox is configured.
	var localFSSession *mcp.ClientSession
	if cfg.Sandbox.Directory != "" {
		expanded, err := expandHome(cfg.Sandbox.Directory)
		if err != nil {
			return nil, fmt.Errorf("expand sandbox dir: %w", err)
		}
		localFSSession, err = localfs.Connect(ctx, expanded)
		if err != nil {
			return nil, fmt.Errorf("start local filesystem server: %w", err)
		}
	}

	var guardClient *GuardClient
	if cfg.Guard.resolvedAPIEndpoint() != "" {
		guardClient = NewGuardClient(cfg.Guard)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Set up oidc-login manager if applicable, otherwise move to authenticated state.
	var oidcLoginMgr *OIDCLoginManager
	if cfg.Identity.Source == "oidc-login" {
		// State machine starts in StateUnauthenticated (the default).
		// The manager will transition states as login progresses.
		oidcLoginMgr = nil // placeholder; we need the Gate struct first
	} else {
		// For os and oidc-file sources, identity is already resolved.
		sm.SetAuthenticated()
	}

	g := &Gate{
		cfg:                cfg,
		identity:           identity,
		store:              store,
		forwarder:          fwd,
		guardClient:        guardClient,
		localFS:            localFSSession,
		sessionID:          uuid.New().String(),
		toolServerMap:      make(map[string]string),
		localFSTools:       make(map[string]bool),
		logChan:            make(chan DecisionLogEntry, 1000),
		logDone:            make(chan struct{}),
		pendingEscalations: make(map[string]pendingEscalation),
		stateMachine:       sm,
	}

	// Create oidc-login manager now that we have the Gate struct (for callbacks).
	if cfg.Identity.Source == "oidc-login" {
		mgmtPort := cfg.ManagementAPI.Port
		if mgmtPort == 0 {
			mgmtPort = DefaultManagementAPIPort
		}
		oidcLoginMgr = NewOIDCLoginManager(
			cfg.Identity.OIDCLogin,
			mgmtPort,
			cfg.Identity.LoginCallbackTimeoutSecs,
			sm,
			func(rawIDToken string) {
				if err := g.identity.SetToken(rawIDToken); err != nil {
					slog.Warn("oidc-login: failed to update identity cache", "error", err)
				}
				// Re-fetch tools from Keep now that we are authenticated.
				// This ensures backend tools are discovered even if discovery
				// failed at startup because the user wasn't logged in yet.
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

	// Start decision log worker
	g.logWg.Add(1)
	go g.logWorker()

	// Fetch tool schemas from Keep and register them with the MCP server.
	// Local filesystem tools are also registered so the agent sees them.
	g.server = mcp.NewServer(&mcp.Implementation{
		Name:    shared.ServiceGate,
		Version: "0.1.0",
	}, nil)

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
			Description: "Starts or checks the Portcullis login process. For oidc-login configurations, returns the URL to open in a browser to authenticate. For os and oidc-file configurations, reports that login is not necessary. Optional 'force' argument (boolean) forces a new login URL even if already authenticated, useful to get a new token from the IdP after it has restarted.",
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

	if localFSSession != nil {
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

// refreshKeepTools fetches tool schemas from Keep and registers them with the
// MCP server. It is called at startup and after successful oidc-login.
func (g *Gate) refreshKeepTools(ctx context.Context) {
	keepTools, err := g.forwarder.ListTools(ctx, g.identity.Get(ctx), g.store.All())
	if err != nil {
		// Non-fatal: gate can still serve local filesystem tools if Keep is
		// temporarily unavailable or user is not yet authenticated.
		slog.Warn("fetch tool list from keep failed", "error", err)
		if g.cfg.Identity.Source != "oidc-login" {
			// For os/oidc-file: record system error for status reporting, but tool
			// calls still proceed (state check only applies to oidc-login source).
			g.stateMachine.SetSystemError(SubstateInvalid, "Keep is unreachable — tool list may be incomplete", err.Error())
		}
		// For oidc-login: tool list will be fetched after login completes. Log only.
		return
	}

	for _, at := range keepTools {
		g.toolServerMap[at.Tool.Name] = at.ServerName
		g.registerTool(at.Tool)
	}
	slog.Info("registered keep tools", "count", len(keepTools))
}

// handleLoginTool handles calls to the portcullis_login tool.
// If force is true, it bypasses the "already authenticated" check and forces a new login URL.
func (g *Gate) handleLoginTool(ctx context.Context, force bool) string {
	switch g.cfg.Identity.Source {
	case "os", "oidc-file":
		return "Login is not necessary."
	case "oidc-login":
		if !force && g.stateMachine.State() == StateAuthenticated {
			return "You are already successfully logged in. Use 'force: true' to get a new login URL (e.g., after IdP restart)."
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
		port := g.cfg.ManagementAPI.Port
		if port == 0 {
			port = DefaultManagementAPIPort
		}
		return fmt.Sprintf("Please open the following URL in your browser to log in:\n%s\n\nThe login URL is also available at: http://localhost:%d/auth/login", loginURL, port)
	}
	return "Login is not necessary."
}

// Run starts the MCP server on stdio transport and blocks until ctx is
// cancelled or the transport closes.
func (g *Gate) Run(ctx context.Context) error {
	mgmt, err := NewManagementServer(g.store, g.identity, g.cfg.ManagementAPI, g.oidcLogin, g.cfg.Identity.LoginCallbackPageFile)
	if err != nil {
		return fmt.Errorf("init management api: %w", err)
	}
	if err := mgmt.Start(ctx); err != nil {
		return fmt.Errorf("start management api: %w", err)
	}

	// Start the Guard poll worker if a Guard endpoint is configured.
	// This discovers tokens approved via remote workflows (e.g. ServiceNow)
	// that Gate would not otherwise learn about until the next tool call.
	// The first poll runs immediately so tokens approved before Gate started
	// (or while Gate was restarting) are claimed without waiting 60 seconds.
	if g.guardClient != nil {
		interval := 60 * time.Second
		if g.cfg.Guard.PollInterval > 0 {
			interval = time.Duration(g.cfg.Guard.PollInterval) * time.Second
		}
		slog.Info("guard poll worker starting", "endpoint", g.cfg.Guard.resolvedAPIEndpoint(), "interval", interval)
		go func() {
			g.claimAllUnclaimedTokens(ctx)
			g.pollGuardWorker(ctx)
		}()
	} else {
		slog.Warn("guard endpoint not configured; escalation tokens must be added manually")
	}

	// Shutdown decision log worker on context cancellation
	go func() {
		<-ctx.Done()
		close(g.logDone)
		g.logWg.Wait() // Wait for worker to flush and exit
	}()

	return g.server.Run(ctx, &mcp.StdioTransport{})
}

// registerTool adds a single tool to the MCP server with a forwarding handler.
// Uses the untyped ToolHandler to avoid SDK output-schema processing that is
// inappropriate for a proxy — we pass the CallToolResult through unchanged.
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

// handleToolCall applies the fast-path, logs the decision, and routes the call
// to either the local filesystem server or Keep.
func (g *Gate) handleToolCall(ctx context.Context, toolName string, args map[string]any) (*mcp.CallToolResult, error) {
	ctx, span := otel.Tracer(shared.ServiceGate).Start(ctx, "gate.tool_call")
	defer span.End()
	span.SetAttributes(
		attribute.String("tool.name", toolName),
		attribute.String("session.id", g.sessionID),
	)

	// State machine check: block tool calls unless authenticated (oidc-login source only).
	// portcullis_status and portcullis_login are always allowed through so the agent
	// can report status and start the login flow.
	if g.cfg.Identity.Source == "oidc-login" && toolName != "portcullis_status" && toolName != "portcullis_login" {
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
		// StateAuthenticated: proceed normally
	}

	// TraceID is the single correlation identifier. Use the OTel trace ID when
	// telemetry is active; fall back to a UUID so logs are always correlatable.
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

		// Queue decision log entry
		select {
		case g.logChan <- DecisionLogEntry{
			Timestamp: time.Now().UTC(),
			SessionID: g.sessionID,
			TraceID:   traceID,
			UserID:    g.identity.Get(ctx).UserID,
			ToolName:  toolName,
			Decision:  "allow",
			Reason:    "sandbox",
			Source:    "gate-fastpath",
			Arguments: args,
		}:
		default:
			// Channel full, skip logging (don't block)
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

		// Queue decision log entry
		select {
		case g.logChan <- DecisionLogEntry{
			Timestamp: time.Now().UTC(),
			SessionID: g.sessionID,
			TraceID:   traceID,
			UserID:    g.identity.Get(ctx).UserID,
			ToolName:  toolName,
			Decision:  "deny",
			Reason:    "protected path",
			Source:    "gate-fastpath",
			Arguments: args,
		}:
		default:
			// Channel full, skip logging (don't block)
		}

		return nil, shared.ErrDenied
	}

	currentIdentity := g.identity.Get(ctx)

	// Local filesystem tools: ask Keep to authorize, then execute locally if allowed.
	// This ensures all non-fast-path filesystem ops are policy-checked and audited.
	if g.localFSTools[toolName] {
		enriched := shared.EnrichedMCPRequest{
			APIVersion:       shared.APIVersion,
			ServerName:       shared.LocalFSServerName,
			ToolName:         toolName,
			Arguments:        args,
			UserIdentity:     currentIdentity,
			EscalationTokens: g.collectEscalationTokens(ctx, shared.LocalFSServerName, toolName),
			SessionID:        g.sessionID,
			TraceID:          traceID,
		}
		if err := g.forwarder.Authorize(ctx, enriched); err != nil {
			if storeErr := g.maybeStorePendingEscalation(ctx, shared.LocalFSServerName, toolName, err); storeErr != nil {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: storeErr.Error()}}}, nil
			}
			return g.policyErrToResult(err, toolName, traceID)
		}
		if g.localFS == nil {
			return nil, fmt.Errorf("local filesystem server not configured")
		}
		return g.localFS.CallTool(ctx, &mcp.CallToolParams{
			Name:      toolName,
			Arguments: args,
		})
	}

	// All other tools: forward to Keep for both authorization and execution.
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
		SessionID:        g.sessionID,
		TraceID:          traceID,
	}
	result, err := g.forwarder.CallTool(ctx, enriched)
	if err != nil {
		if storeErr := g.maybeStorePendingEscalation(ctx, serverName, toolName, err); storeErr != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: storeErr.Error()}}}, nil
		}
		return g.policyErrToResult(err, toolName, traceID)
	}
	return result, err
}

// collectEscalationTokens returns the tokens to include on an outbound request.
// If Guard is configured and there is a pending escalation for this server/tool,
// it attempts to claim the approved token from Guard and adds it to the list.
// The claimed token is also persisted to the local store for future calls.
func (g *Gate) collectEscalationTokens(ctx context.Context, serverName, toolName string) []shared.EscalationToken {
	tokens := g.store.All()

	if g.guardClient == nil {
		return tokens
	}

	key := serverName + "/" + toolName
	g.pendingMu.Lock()
	pending, hasPending := g.pendingEscalations[key]
	g.pendingMu.Unlock()

	if !hasPending {
		return tokens
	}
	if pending.ExpiresAt.Before(time.Now()) {
		// Pending entry has expired; remove it.
		g.pendingMu.Lock()
		delete(g.pendingEscalations, key)
		g.pendingMu.Unlock()
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
		// Token not yet approved — proceed without it.
		return tokens
	}

	tok, err := g.store.Add(ctx, raw)
	if err != nil {
		slog.Warn("store claimed escalation token failed", "jti", pending.JTI, "error", err)
		return tokens
	}

	slog.Info("claimed escalation token from guard",
		"jti", pending.JTI, "token_id", tok.TokenID,
		"server", serverName, "tool", toolName)

	// Remove from pending — token is now in the store.
	g.pendingMu.Lock()
	delete(g.pendingEscalations, key)
	g.pendingMu.Unlock()

	return g.store.All()
}

// maybeStorePendingEscalation records a pending escalation in the in-memory map
// when Keep responds with an escalation-required error that carries a JTI.
// In proactive mode it also pushes the signed JWT to Guard immediately so that
// Guard can serve a short ?jti= approval URL. Returns an error (shown to the
// agent) only when Guard is unreachable in proactive mode.
//
// When Guard is not configured, this is a no-op: the pending escalation cannot
// be resolved (no poll worker runs), and policyErrToResult will convert the
// escalation to a deny regardless.
func (g *Gate) maybeStorePendingEscalation(ctx context.Context, serverName, toolName string, err error) error {
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
			return fmt.Errorf("escalation required but Guard is currently unreachable — please try again later")
		}
		slog.Info("proactive: registered pending escalation with Guard",
			"jti", escalationErr.EscalationJTI, "server", serverName, "tool", toolName)
	}

	key := serverName + "/" + toolName
	// Default TTL of 24 hours; the JWT's own exp will enforce the real deadline at Guard.
	expiry := time.Now().Add(24 * time.Hour)

	g.pendingMu.Lock()
	g.pendingEscalations[key] = pendingEscalation{
		ServerName: serverName,
		ToolName:   toolName,
		JTI:        escalationErr.EscalationJTI,
		ExpiresAt:  expiry,
	}
	g.pendingMu.Unlock()

	slog.Info("stored pending escalation",
		"server", serverName, "tool", toolName, "jti", escalationErr.EscalationJTI)
	return nil
}

// isProactive reports whether Gate is configured to push pending escalation JWTs
// to Guard proactively (approval_management_strategy: "proactive").
func (g *Gate) isProactive() bool {
	return g.cfg.Guard.ApprovalManagementStrategy == "proactive"
}

// defaultRequireApprovalInstructions is the built-in escalation/workflow message template.
// Supports {reason}, {url}, and {trace_id} placeholders.
const defaultRequireApprovalInstructions = "Escalation required: {reason}\n\nPresent this complete URL to the user so they can click it to approve the request. Do not truncate or shorten the URL:\n{url}\n\nTrace ID: {trace_id}"

// defaultDenyInstructions is the built-in deny message template.
// Supports {reason} and {trace_id} placeholders.
const defaultDenyInstructions = "Access denied: {reason}\n\nIf you believe this is incorrect, contact your security team and reference trace ID: {trace_id}"

// buildDenyMessage constructs the agent-facing message for a deny response,
// substituting {reason} and {trace_id} in the configured deny instructions template.
func (g *Gate) buildDenyMessage(reason, traceID string) string {
	instructions := g.cfg.Agent.Deny.Instructions
	if instructions == "" {
		instructions = defaultDenyInstructions
	}
	msg := strings.ReplaceAll(instructions, "{reason}", reason)
	msg = strings.ReplaceAll(msg, "{trace_id}", traceID)
	return msg
}

// buildEscalationMessage constructs the agent-facing message for an escalation
// response, substituting {reason}, {url}, and {trace_id} in the configured
// instructions template.
func (g *Gate) buildEscalationMessage(e *shared.EscalationPendingError, traceID string) string {
	guardEndpoint := g.cfg.Guard.EscalationApprovalEndpoint

	var approvalURL string
	if guardEndpoint != "" {
		if g.isProactive() && e.EscalationJTI != "" {
			approvalURL = guardEndpoint + "/approve?jti=" + url.QueryEscape(e.EscalationJTI)
		} else if e.PendingJWT != "" {
			approvalURL = guardEndpoint + "/approve?token=" + url.QueryEscape(e.PendingJWT)
		}
	}
	// Fall back to any reference URL Keep provided directly (e.g. ServiceNow ticket URL).
	if approvalURL == "" && e.Reference != "" {
		approvalURL = e.Reference
	}

	// If no URL could be constructed from any source, the escalation cannot be
	// actioned. Return a clear message rather than a broken template with an
	// empty {url} substitution. This is a defensive fallback — Keep should have
	// already returned 500 in this situation.
	if approvalURL == "" {
		slog.Warn("escalation required but no approval URL available — check Keep escalation_request_signing configuration",
			"reason", e.Reason)
		msg := "Escalation required: " + e.Reason
		if msg != "" {
			msg += "\n\nNo approval URL is available. The escalation system may be misconfigured — please contact your administrator."
		}
		return msg
	}

	instructions := g.cfg.Agent.RequireApproval.Instructions
	if instructions == "" {
		instructions = defaultRequireApprovalInstructions
	}

	msg := strings.ReplaceAll(instructions, "{reason}", e.Reason)
	msg = strings.ReplaceAll(msg, "{url}", approvalURL)
	msg = strings.ReplaceAll(msg, "{trace_id}", traceID)
	return msg
}

// pollGuardWorker periodically fetches the unclaimed token list from Guard for
// the current user. This discovers tokens approved by remote workflows (e.g.
// ServiceNow calling /token/deposit) that Gate would not otherwise learn about.
func (g *Gate) pollGuardWorker(ctx context.Context) {
	interval := 60 * time.Second
	if g.cfg.Guard.PollInterval > 0 {
		interval = time.Duration(g.cfg.Guard.PollInterval) * time.Second
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

// claimAllUnclaimedTokens fetches the unclaimed token list from Guard and
// claims every token it finds, adding each to the local store and removing the
// corresponding entry from the pending escalations map.
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
			slog.Warn("guard poll: token listed as unclaimed but claim returned empty (already claimed or race)", "jti", entry.JTI)
			continue
		}

		tok, storeErr := g.store.Add(ctx, raw)
		if storeErr != nil {
			slog.Warn("store polled token failed", "jti", entry.JTI, "error", storeErr)
			continue
		}

		slog.Info("claimed escalation token via poll", "jti", entry.JTI, "token_id", tok.TokenID)

		// Remove any matching pending escalation entry by JTI.
		g.pendingMu.Lock()
		for key, p := range g.pendingEscalations {
			if p.JTI == entry.JTI {
				delete(g.pendingEscalations, key)
				break
			}
		}
		g.pendingMu.Unlock()
	}
}

// policyErrToResult converts a policy error (deny or escalation) from Keep into
// an MCP tool-level error result so the agent reads the message rather than
// seeing a JSON-RPC protocol error.
func (g *Gate) policyErrToResult(err error, toolName, traceID string) (*mcp.CallToolResult, error) {
	var escalationErr *shared.EscalationPendingError
	var denyErr *shared.DenyError
	var identityErr *shared.IdentityVerificationError
	switch {
	case errors.As(err, &escalationErr):
		// Prefer the trace ID Keep sent back — it matches Keep's OTel spans and
		// slog entries. Fall back to Gate's local ID only when Keep didn't send one
		// (e.g. older Keep version or Keep also running noop telemetry).
		effectiveTraceID := escalationErr.TraceID
		if effectiveTraceID == "" {
			effectiveTraceID = traceID
		}
		// Without a Guard endpoint Gate cannot poll for or claim escalation tokens,
		// so escalation can never complete. Treat it as a deny so the agent does
		// not present the user with an approval flow that will never resolve.
		if g.cfg.Guard.resolvedAPIEndpoint() == "" {
			slog.Warn("escalation required but Guard is not configured — treating as deny",
				"tool", toolName, "reason", escalationErr.Reason)
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
		// Same preference: use Keep's trace ID so the user can find it in Keep's logs.
		effectiveTraceID := denyErr.TraceID
		if effectiveTraceID == "" {
			effectiveTraceID = traceID
		}
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: g.buildDenyMessage(denyErr.Reason, effectiveTraceID)}},
		}, nil
	case errors.As(err, &identityErr):
		// Identity token is invalid (e.g., JWKS kid mismatch after IdP restart).
		// Reset to unauthenticated state and prompt user to log in again.
		slog.Warn("identity verification failed, resetting to unauthenticated", 
			"error", identityErr.Reason, "trace_id", traceID)
		if g.cfg.Identity.Source == "oidc-login" {
			g.stateMachine.SetUnauthenticated()
			g.identity.Clear()
			loginMsg := g.handleLoginTool(context.Background(), false)
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: "Your authentication has expired. " + loginMsg}},
			}, nil
		}
		// For non-oidc-login sources, return the error as-is
		return nil, err
	case errors.Is(err, shared.ErrDenied):
		// Fallback for bare sentinel (e.g. fast-path deny reaching this code path).
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: g.buildDenyMessage("", traceID)}},
		}, nil
	}
	slog.Error("keep call failed", "error", err, "tool", toolName, "request_id", traceID)
	return nil, err
}

// logWorker batches decision log entries and sends them to Keep periodically.
func (g *Gate) logWorker() {
	defer g.logWg.Done()

	flushInterval := 30 * time.Second // default
	if g.cfg.DecisionLogs.FlushInterval > 0 {
		flushInterval = time.Duration(g.cfg.DecisionLogs.FlushInterval) * time.Second
	}

	maxBatchSize := 100 // default
	if g.cfg.DecisionLogs.MaxBatchSize > 0 {
		maxBatchSize = g.cfg.DecisionLogs.MaxBatchSize
	}

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	var batch []DecisionLogEntry

	for {
		select {
		case <-g.logDone:
			// Drain remaining entries and flush
			for {
				select {
				case entry := <-g.logChan:
					batch = append(batch, entry)
				default:
					// Channel is empty
					if len(batch) > 0 {
						g.flushLogs(batch)
					}
					return
				}
			}

		case entry := <-g.logChan:
			batch = append(batch, entry)

			// Flush if batch reaches max size
			if len(batch) >= maxBatchSize {
				g.flushLogs(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			// Periodic flush
			if len(batch) > 0 {
				g.flushLogs(batch)
				batch = batch[:0]
			}
		}
	}
}

// flushLogs sends a batch of decision log entries to Keep.
func (g *Gate) flushLogs(entries []DecisionLogEntry) {
	if len(entries) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := g.forwarder.SendLogs(ctx, entries); err != nil {
		slog.Warn("failed to send decision logs to keep", "error", err, "count", len(entries))
		// Don't retry - just log the error
	} else {
		slog.Debug("sent decision logs to keep", "count", len(entries))
	}
}
